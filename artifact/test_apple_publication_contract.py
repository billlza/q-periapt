#!/usr/bin/env python3
"""Fail-closed tests for versioned Apple publication receipts."""

from __future__ import annotations

import copy
import json
import operator
import pathlib
import unittest

import apple_distribution
import apple_publication_contract as contract
import crates_io_publication_contract as crates_contract
import platform_publication_contract as platform_contract
import release_publication_contract as release_contract


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _digest(index: int) -> str:
    return f"{index:064x}"


def source_baseline_manifest() -> dict[str, object]:
    """Return the live manifest reduced to the frozen source-results baseline.

    The committed results.json is a state-selected manifest: the stable
    0.1.3 cohort leaves are either absent (source state), pending, or
    verified, and the Apple selector advances with them. Fixtures that
    construct synthetic cohort states must start from the state-independent
    source baseline instead of inheriting whichever cohort state happens to
    be installed, so this strips the stable 0.1.3 cohort leaves and restores
    the complete neutral alpha.2-r1 selector projection: a pre-migration
    legacy manifest defers to the production one-time migration, and an
    already-migrated selector is rebuilt from the frozen neutral field set
    (byte-identical under the pending state).
    """

    live = json.loads(
        (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
    )
    publications = live["release_publications"]
    for key in (
        contract.APPLE_V0_1_3_PUBLICATION_KEY,
        platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
        crates_contract.CRATES_IO_PUBLICATION_KEY,
    ):
        publications.pop(key, None)
    swift = live["swift_xcframework"]
    if "active_publication_key" not in swift:
        # The initial baseline predates the one-time selector migration and
        # still carries the exact frozen legacy alpha.2 selector, so the
        # production migration itself produces the neutral projection.
        live["swift_xcframework"] = release_contract.neutral_swift_selector(
            live
        )
        return live
    swift.update(
        {
            "active_publication_key": (
                contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            ),
            "boundary": release_contract.NEUTRAL_SWIFT_BOUNDARY,
            "command": release_contract.NEUTRAL_SWIFT_COMMAND,
            "current_local_status": (
                release_contract.NEUTRAL_SWIFT_LOCAL_STATUS
            ),
            "current_source_status": (
                release_contract.NEUTRAL_SWIFT_SOURCE_STATUS
            ),
            "distribution": contract.frozen_alpha2_r1_distribution(),
            "mode": release_contract.NEUTRAL_SWIFT_MODE,
        }
    )
    return live


def alpha2_receipt() -> dict[str, object]:
    return {
        "boundary": contract.APPLE_ALPHA2_R1_BOUNDARY,
        "distribution": contract.frozen_alpha2_r1_distribution(),
        "identity": copy.deepcopy(contract.APPLE_ALPHA2_R1_IDENTITY),
        "kind": contract.APPLE_PUBLICATION_KIND,
        "publication": contract.frozen_alpha2_r1_publication(),
        "schema_version": contract.APPLE_PUBLICATION_SCHEMA_VERSION,
        "status": contract.APPLE_STATUS_VERIFIED,
    }


def stable_pending_receipt() -> dict[str, object]:
    distribution = {
        "apple_distribution_evidence_sha256": _digest(1),
        "artifact_path": "CQPeriapt.xcframework.zip",
        "artifact_sha256": _digest(2),
        "artifact_size": 44_000_000,
        "checksums_sha256": _digest(3),
        "distribution_signed": True,
        "immutable_release": False,
        "manifest_sha256": _digest(4),
        "notarization_applicability": "not_applicable_static_sdk_payload",
        "notarized": False,
        "origin_signature_certificate_sha256": _digest(5),
        "origin_signature_identity_class": "Developer ID Application",
        "origin_signature_team_id": "YKUPL7Z869",
        "public_release": False,
        "release_revision": "r1",
        "release_tag": "v0.1.3",
        "release_url": (
            "https://github.com/billlza/q-periapt/releases/tag/"
            "v0.1.3"
        ),
        "remote_consumer_verified": False,
        "remote_verification": {
            "log_sha256": None,
            "verified_at": None,
            "verifier_commit": None,
        },
        "source_commit": "1" * 40,
        "stapled": False,
        "swiftpm_checksum": _digest(2),
        "version": "0.1.3",
    }
    return {
        "boundary": contract.APPLE_V0_1_3_BOUNDARY,
        "distribution": distribution,
        "identity": copy.deepcopy(contract.APPLE_V0_1_3_IDENTITY),
        "kind": contract.APPLE_PUBLICATION_KIND,
        "schema_version": contract.APPLE_PUBLICATION_SCHEMA_VERSION,
        "source": {
            "canonical_source_tree_sha256": _digest(8),
            "source_parent_commit": distribution["source_commit"],
            "tag_commit": "4" * 40,
            "tag_object": "3" * 40,
            "tag_tree": "5" * 40,
        },
        "status": contract.APPLE_STATUS_PENDING,
    }


def stable_verified_receipt() -> dict[str, object]:
    receipt = stable_pending_receipt()
    receipt["status"] = contract.APPLE_STATUS_VERIFIED
    distribution = receipt["distribution"]
    distribution["public_release"] = True
    distribution["immutable_release"] = True
    distribution["remote_consumer_verified"] = True
    distribution["remote_verification"] = {
        "log_sha256": _digest(6),
        "verified_at": "2026-08-14T12:00:00Z",
        "verifier_commit": "2" * 40,
    }
    tag_object = receipt["source"]["tag_object"]
    public_asset_sha256s = contract.apple_public_asset_sha256s(distribution)
    receipt["publication"] = {
        "draft": False,
        "immutable_release": True,
        "observed_at": "2026-08-14T13:00:00Z",
        "prerelease": False,
        "public_release": True,
        "published_at": "2026-08-14T10:00:00Z",
        "release_attestation": {
            "certificate_san": contract.APPLE_RELEASE_CERTIFICATE_SAN,
            "predicate_type": contract.APPLE_RELEASE_PREDICATE_TYPE,
            "subjects": [
                {
                    "digest": {"sha1": tag_object},
                    "uri": (
                        contract.APPLE_TAG_SUBJECT_PREFIX
                        + "v0.1.3"
                    ),
                },
                *[
                    {
                        "digest": {"sha256": public_asset_sha256s[name]},
                        "name": name,
                    }
                    for name in contract.APPLE_PUBLIC_ASSET_NAMES
                ],
            ],
            "verification_record_sha256": _digest(7),
            "verified": True,
            "verified_at": "2026-08-14T10:01:00Z",
        },
        "release_id": 355_500_000,
        "source": {
            "tag_commit": receipt["source"]["tag_commit"],
            "tag_object": tag_object,
        },
    }
    return receipt


def manifest(*receipts: tuple[str, dict[str, object]]) -> dict[str, object]:
    return {"release_publications": dict(receipts)}


class ApplePublicationContractTests(unittest.TestCase):
    def test_current_stable_producer_matches_frozen_leaf_literals(self) -> None:
        self.assertEqual(
            {
                "distribution_revision": apple_distribution.RELEASE_REVISION,
                "product_version": apple_distribution.PRODUCT_VERSION,
                "release_tag": apple_distribution.RELEASE_TAG,
                "release_url": apple_distribution.RELEASE_URL,
            },
            contract.APPLE_V0_1_3_IDENTITY,
        )
        self.assertEqual(
            apple_distribution.XCFRAMEWORK_ZIP_NAME,
            contract.APPLE_XCFRAMEWORK_ARTIFACT_PATH,
        )
        self.assertEqual(
            apple_distribution.EXPECTED_IDENTITY_CLASS,
            contract.APPLE_ORIGIN_IDENTITY_CLASS,
        )
        self.assertEqual(
            (
                apple_distribution.APPLE_DISTRIBUTION_NAME,
                apple_distribution.XCFRAMEWORK_ZIP_NAME,
                apple_distribution.MANIFEST_NAME,
                apple_distribution.SHA256SUMS_NAME,
            ),
            contract.APPLE_PUBLIC_ASSET_NAMES,
        )
        self.assertEqual(
            contract.APPLE_PUBLIC_ASSET_NAMES,
            tuple(contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES),
        )
        self.assertEqual(
            {
                contract.APPLE_DISTRIBUTION_ASSET_PATH: "application/json",
                contract.APPLE_XCFRAMEWORK_ARTIFACT_PATH: "application/zip",
                contract.APPLE_MANIFEST_ASSET_PATH: "application/json",
                contract.APPLE_CHECKSUMS_ASSET_PATH: (
                    "application/octet-stream"
                ),
            },
            dict(contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES),
        )
        with self.assertRaises(TypeError):
            operator.setitem(
                contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES,
                contract.APPLE_DISTRIBUTION_ASSET_PATH,
                "application/octet-stream",
            )
        self.assertEqual(
            contract.APPLE_PUBLIC_ASSET_NAMES,
            tuple(
                contract.apple_public_asset_sha256s(
                    contract.frozen_alpha2_r1_distribution()
                )
            ),
        )

    def test_alpha2_leaf_exactly_freezes_the_current_legacy_projection(self) -> None:
        results = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            results["release_publications"][
                contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            ],
            alpha2_receipt(),
        )
        contract.validate_apple_publications(
            {
                "release_publications": {
                    key: receipt
                    for key, receipt in results[
                        "release_publications"
                    ].items()
                    if key in contract.APPLE_PUBLICATION_KEYS
                }
            }
        )
        selector = results["swift_xcframework"]
        active_key = selector.get("active_publication_key")
        if active_key is None:
            # Pre-migration legacy manifest: the initial baseline selector
            # still carries the legacy prose, has no active publication
            # key, and must freeze the alpha.2-r1 projection byte for byte.
            self.assertEqual(
                selector["distribution"],
                contract.frozen_alpha2_r1_distribution(),
            )
        elif active_key == contract.APPLE_ALPHA2_R1_PUBLICATION_KEY:
            # Legacy selection: the live projection is the frozen alpha.2-r1
            # distribution, byte for byte.
            self.assertEqual(
                selector["distribution"],
                contract.frozen_alpha2_r1_distribution(),
            )
        else:
            # The selector may only ever advance to the verified 0.1.3
            # stable receipt; it must then repeat that receipt's
            # distribution projection exactly.
            self.assertEqual(
                active_key, contract.APPLE_V0_1_3_PUBLICATION_KEY
            )
            stable = results["release_publications"][
                contract.APPLE_V0_1_3_PUBLICATION_KEY
            ]
            self.assertEqual(
                stable["status"], contract.APPLE_STATUS_VERIFIED
            )
            self.assertEqual(
                selector["distribution"], stable["distribution"]
            )
        contract.validate_apple_publications(
            manifest((contract.APPLE_ALPHA2_R1_PUBLICATION_KEY, alpha2_receipt()))
        )

        for field, value in (
            ("artifact_size", 33_325_899),
            ("source_commit", "3" * 40),
            ("origin_signature_team_id", "ABCDEFGHIJ"),
        ):
            with self.subTest(field=field):
                changed = alpha2_receipt()
                changed["distribution"][field] = value
                with self.assertRaises(
                    contract.ApplePublicationContractError
                ):
                    contract.validate_apple_publications(
                        manifest(
                            (
                                contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
                                changed,
                            )
                        )
                    )

    def test_stable_states_are_exact_and_cross_link_identity(self) -> None:
        for receipt in (stable_pending_receipt(), stable_verified_receipt()):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, receipt))
            )

        invalid = stable_pending_receipt()
        invalid["distribution"]["public_release"] = True
        invalid["distribution"]["immutable_release"] = True
        with self.assertRaisesRegex(
            contract.ApplePublicationContractError,
            "state differs from its status",
        ):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, invalid))
            )

        invalid = stable_pending_receipt()
        invalid["distribution"]["release_tag"] = "v0.1.0-alpha.2-r1"
        with self.assertRaises(contract.ApplePublicationContractError):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, invalid))
            )

        for field, value, message in (
            ("source_parent_commit", "4" * 40, "differ from its source parent"),
            ("canonical_source_tree_sha256", "x" * 64, "lowercase SHA-256"),
            ("tag_tree", "x" * 40, "lowercase SHA-1"),
        ):
            with self.subTest(source_field=field):
                invalid = stable_pending_receipt()
                invalid["source"][field] = value
                with self.assertRaisesRegex(
                    contract.ApplePublicationContractError, message
                ):
                    contract.validate_apple_publications(
                        manifest(
                            (contract.APPLE_V0_1_3_PUBLICATION_KEY, invalid)
                        )
                    )

        invalid = stable_pending_receipt()
        invalid["schema_version"] = True
        with self.assertRaisesRegex(
            contract.ApplePublicationContractError, "schema differs"
        ):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, invalid))
            )

        for invalid_status in ([], {}):
            with self.subTest(invalid_status=type(invalid_status).__name__):
                invalid = stable_pending_receipt()
                invalid["status"] = invalid_status
                with self.assertRaisesRegex(
                    contract.ApplePublicationContractError,
                    "status must be a string",
                ):
                    contract.validate_apple_publications(
                        manifest(
                            (
                                contract.APPLE_V0_1_3_PUBLICATION_KEY,
                                invalid,
                            )
                        )
                    )

    def test_publication_is_verified_only_and_exactly_cross_linked(self) -> None:
        pending = stable_pending_receipt()
        pending["publication"] = copy.deepcopy(
            stable_verified_receipt()["publication"]
        )
        with self.assertRaisesRegex(
            contract.ApplePublicationContractError, "keys differ"
        ):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, pending))
            )

        missing = stable_verified_receipt()
        missing.pop("publication")
        with self.assertRaisesRegex(
            contract.ApplePublicationContractError, "keys differ"
        ):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, missing))
            )

        for label, mutate, message in (
            (
                "subject",
                lambda receipt: receipt["publication"][
                    "release_attestation"
                ]["subjects"][1]["digest"].update({"sha256": _digest(99)}),
                "subjects differ",
            ),
            (
                "tag-commit",
                lambda receipt: receipt["publication"]["source"].update(
                    {"tag_commit": "6" * 40}
                ),
                "tag identity differs",
            ),
            (
                "time-order",
                lambda receipt: receipt["publication"].update(
                    {"observed_at": "2026-08-14T11:00:00Z"}
                ),
                "timestamps are out of order",
            ),
            (
                "release-id-type",
                lambda receipt: receipt["publication"].update(
                    {"release_id": True}
                ),
                "positive integer",
            ),
        ):
            with self.subTest(label=label):
                changed = stable_verified_receipt()
                mutate(changed)
                with self.assertRaisesRegex(
                    contract.ApplePublicationContractError, message
                ):
                    contract.validate_apple_publications(
                        manifest(
                            (
                                contract.APPLE_V0_1_3_PUBLICATION_KEY,
                                changed,
                            )
                        )
                    )

    def test_release_attestation_mutation_matrix_fails_closed(self) -> None:
        scalar_mutations = (
            (
                "certificate-san",
                "certificate_san",
                "https://example.invalid",
                "certificate identity differs",
            ),
            (
                "predicate",
                "predicate_type",
                "https://example.invalid/predicate",
                "predicate differs",
            ),
            ("verified-int", "verified", 1, "must be verified"),
            ("verified-list", "verified", [], "must be verified"),
            (
                "verification-record",
                "verification_record_sha256",
                "g" * 64,
                "must be a lowercase SHA-256",
            ),
        )
        for label, field, value, message in scalar_mutations:
            with self.subTest(label=label):
                receipt = stable_verified_receipt()
                receipt["publication"]["release_attestation"][field] = value
                with self.assertRaisesRegex(
                    contract.ApplePublicationContractError, message
                ):
                    contract.validate_apple_publications(
                        manifest(
                            (
                                contract.APPLE_V0_1_3_PUBLICATION_KEY,
                                receipt,
                            )
                        )
                    )

        subject_mutations = (
            "missing",
            "extra",
            "reorder",
            "tag-uri",
            "tag-digest",
            "apple-distribution-digest",
            "xcframework-digest",
            "manifest-digest",
            "checksums-digest",
        )
        for mutation in subject_mutations:
            with self.subTest(mutation=mutation):
                receipt = stable_verified_receipt()
                subjects = receipt["publication"]["release_attestation"][
                    "subjects"
                ]
                if mutation == "missing":
                    subjects.pop()
                elif mutation == "extra":
                    subjects.append(
                        {
                            "digest": {"sha256": _digest(98)},
                            "name": "EXTRA.bin",
                        }
                    )
                elif mutation == "reorder":
                    subjects[1], subjects[2] = subjects[2], subjects[1]
                elif mutation == "tag-uri":
                    subjects[0]["uri"] = (
                        "pkg:github/billlza/q-periapt@v0.1.0-r2"
                    )
                elif mutation == "tag-digest":
                    subjects[0]["digest"]["sha1"] = "4" * 40
                else:
                    asset_index = {
                        "apple-distribution-digest": 1,
                        "xcframework-digest": 2,
                        "manifest-digest": 3,
                        "checksums-digest": 4,
                    }[mutation]
                    subjects[asset_index]["digest"]["sha256"] = _digest(99)
                with self.assertRaisesRegex(
                    contract.ApplePublicationContractError,
                    "release attestation subjects differ",
                ):
                    contract.validate_apple_publications(
                        manifest(
                            (
                                contract.APPLE_V0_1_3_PUBLICATION_KEY,
                                receipt,
                            )
                        )
                    )

    def test_transition_matrix_is_monotonic(self) -> None:
        empty: dict[str, object] = {}
        alpha2 = manifest(
            (contract.APPLE_ALPHA2_R1_PUBLICATION_KEY, alpha2_receipt())
        )
        pending = manifest(
            (contract.APPLE_V0_1_3_PUBLICATION_KEY, stable_pending_receipt())
        )
        verified = manifest(
            (contract.APPLE_V0_1_3_PUBLICATION_KEY, stable_verified_receipt())
        )
        both = manifest(
            (contract.APPLE_ALPHA2_R1_PUBLICATION_KEY, alpha2_receipt()),
            (
                contract.APPLE_V0_1_3_PUBLICATION_KEY,
                stable_pending_receipt(),
            ),
        )
        for label, previous, current in (
            ("empty", empty, empty),
            ("add-pending", empty, pending),
            ("same-alpha2", alpha2, copy.deepcopy(alpha2)),
            ("same-pending", pending, copy.deepcopy(pending)),
            ("same-verified", verified, copy.deepcopy(verified)),
            ("promote", pending, verified),
        ):
            with self.subTest(label=label):
                contract.validate_apple_publication_transition(previous, current)

        for label, current in (("add-alpha2", alpha2), ("add-both", both)):
            with self.subTest(label=label), self.assertRaisesRegex(
                contract.ApplePublicationContractError,
                "historical Apple alpha.2.*cannot be introduced",
            ):
                contract.validate_apple_publication_transition(empty, current)

        with self.assertRaisesRegex(
            contract.ApplePublicationContractError,
            "must first be recorded as pending",
        ):
            contract.validate_apple_publication_transition(empty, verified)

    def test_transition_rejects_removal_demotion_and_candidate_drift(self) -> None:
        alpha2 = manifest(
            (contract.APPLE_ALPHA2_R1_PUBLICATION_KEY, alpha2_receipt())
        )
        pending = manifest(
            (contract.APPLE_V0_1_3_PUBLICATION_KEY, stable_pending_receipt())
        )
        verified = manifest(
            (contract.APPLE_V0_1_3_PUBLICATION_KEY, stable_verified_receipt())
        )
        changed_pending = copy.deepcopy(pending)
        changed_pending["release_publications"][
            contract.APPLE_V0_1_3_PUBLICATION_KEY
        ]["distribution"]["artifact_size"] += 1
        drifted_promotion = copy.deepcopy(verified)
        drifted_promotion["release_publications"][
            contract.APPLE_V0_1_3_PUBLICATION_KEY
        ]["distribution"]["origin_signature_certificate_sha256"] = _digest(9)
        changed_verified = copy.deepcopy(verified)
        changed_verified["release_publications"][
            contract.APPLE_V0_1_3_PUBLICATION_KEY
        ]["distribution"]["remote_verification"]["verified_at"] = (
            "2026-08-14T13:00:00Z"
        )
        for label, previous, current, message in (
            ("remove-alpha2", alpha2, {}, "alpha.2.*cannot be removed"),
            ("remove-stable", pending, {}, "0.1.3 stable.*cannot be removed"),
            (
                "change-pending",
                pending,
                changed_pending,
                "pending.*only remain unchanged",
            ),
            (
                "candidate-drift",
                pending,
                drifted_promotion,
                "changed signed candidate fact",
            ),
            (
                "verified-drift",
                verified,
                changed_verified,
                "verified.*cannot change",
            ),
            (
                "demotion",
                verified,
                pending,
                "verified.*cannot change",
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    contract.ApplePublicationContractError, message
                ):
                    contract.validate_apple_publication_transition(
                        previous, current
                    )

    def test_unknown_keys_and_receipt_fields_fail_closed(self) -> None:
        receipt = stable_pending_receipt()
        receipt["unexpected"] = None
        with self.assertRaisesRegex(
            contract.ApplePublicationContractError, "keys differ"
        ):
            contract.validate_apple_publications(
                manifest((contract.APPLE_V0_1_3_PUBLICATION_KEY, receipt))
            )
        with self.assertRaisesRegex(
            contract.ApplePublicationContractError, "unknown Apple entries"
        ):
            contract.validate_apple_publications(
                {"release_publications": {"apple_alpha4": {}}}
            )


if __name__ == "__main__":
    unittest.main()
