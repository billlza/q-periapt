#!/usr/bin/env python3
"""Real-Git finalizer integration for the one-time Apple receipt migration."""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

import apple_publication_contract as apple_contract
import proof_to_byte_finalizer
from test_apple_publication_contract import (
    alpha2_receipt,
    alpha3_pending_receipt,
    alpha3_verified_receipt,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _git(root: pathlib.Path, *arguments: str) -> None:
    subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _commit(root: pathlib.Path, message: str) -> None:
    _git(root, "add", "--all")
    _git(
        root,
        "-c",
        "user.name=Publication Test",
        "-c",
        "user.email=publication@example.invalid",
        "commit",
        "-qm",
        message,
    )


def _repository_with_parent_results(
    root: pathlib.Path, parent: dict[str, object]
) -> None:
    subprocess.run(
        ["/usr/bin/git", "init", "-q", str(root)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    artifact = root / "artifact"
    artifact.mkdir()
    (artifact / "results.json").write_text(
        json.dumps(parent, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _commit(root, "Record parent publication results")
    (root / "successor.txt").write_text("successor\n", encoding="utf-8")
    _commit(root, "Record successor")


class ApplePublicationFinalizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.legacy = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        publications = cls.legacy.setdefault("release_publications", {})
        for key in apple_contract.APPLE_PUBLICATION_KEYS:
            publications.pop(key, None)
        cls.legacy.setdefault("swift_xcframework", {})[
            "distribution"
        ] = apple_contract.frozen_alpha2_r1_distribution()
        if any(
            key in publications for key in apple_contract.APPLE_PUBLICATION_KEYS
        ) or not apple_contract.publication_values_equal(
            cls.legacy["swift_xcframework"]["distribution"],
            apple_contract.frozen_alpha2_r1_distribution(),
        ):
            raise AssertionError(
                "legacy fixture must be the exact selector-only Apple alpha.2 state"
            )

    def test_exact_legacy_first_parent_can_add_frozen_alpha2_receipt(self) -> None:
        current = copy.deepcopy(self.legacy)
        current["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, self.legacy)
            proof_to_byte_finalizer.validate_release_publication_history(
                root, current
            )

            with_alpha3 = copy.deepcopy(current)
            with_alpha3["release_publications"][
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
            ] = alpha3_pending_receipt()
            proof_to_byte_finalizer.validate_release_publication_history(
                root, with_alpha3
            )

    def test_legacy_migration_requires_alpha2_leaf_and_preserved_projection(
        self,
    ) -> None:
        missing_alpha2 = copy.deepcopy(self.legacy)
        alpha3 = alpha3_pending_receipt()
        missing_alpha2["release_publications"][
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        ] = alpha3
        missing_alpha2["swift_xcframework"]["distribution"] = copy.deepcopy(
            alpha3["distribution"]
        )
        changed_projection = copy.deepcopy(self.legacy)
        changed_projection["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        changed_projection["swift_xcframework"]["distribution"][
            "artifact_size"
        ] += 1
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, self.legacy)
            for label, current in (
                ("missing-alpha2", missing_alpha2),
                ("changed-projection", changed_projection),
            ):
                with self.subTest(label=label), self.assertRaises(
                    proof_to_byte_finalizer.FinalizerError
                ):
                    proof_to_byte_finalizer.validate_release_publication_history(
                        root, current
                    )

    def test_post_migration_first_parent_cannot_return_to_legacy_only(self) -> None:
        migrated = copy.deepcopy(self.legacy)
        migrated["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        rollback = copy.deepcopy(self.legacy)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, migrated)
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "versioned Apple publication receipt",
            ):
                proof_to_byte_finalizer.validate_release_publication_history(
                    root, rollback
                )

    def test_first_parent_cannot_skip_pending_and_add_verified_alpha3(self) -> None:
        migrated = copy.deepcopy(self.legacy)
        migrated["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        direct_verified = copy.deepcopy(migrated)
        verified = alpha3_verified_receipt()
        direct_verified["release_publications"][
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        ] = verified
        direct_verified["swift_xcframework"]["distribution"] = copy.deepcopy(
            verified["distribution"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, migrated)
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "must first be recorded as pending",
            ):
                proof_to_byte_finalizer.validate_release_publication_history(
                    root, direct_verified
                )

    def test_nonexact_legacy_projection_does_not_receive_migration_exception(
        self,
    ) -> None:
        previous = copy.deepcopy(self.legacy)
        previous["swift_xcframework"]["distribution"]["artifact_size"] += 1
        current = copy.deepcopy(self.legacy)
        current["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, previous)
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "requires a versioned Apple publication receipt",
            ):
                proof_to_byte_finalizer.validate_release_publication_history(
                    root, current
                )

    def test_first_parent_rejects_nonlegacy_alpha2_introduction(self) -> None:
        no_selector = copy.deepcopy(self.legacy)
        no_selector["swift_xcframework"].pop("distribution")
        from_no_selector = copy.deepcopy(no_selector)
        from_no_selector["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        from_no_selector["swift_xcframework"]["distribution"] = (
            apple_contract.frozen_alpha2_r1_distribution()
        )

        alpha3_parent = copy.deepcopy(no_selector)
        pending = alpha3_pending_receipt()
        alpha3_parent["release_publications"][
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        ] = pending
        alpha3_parent["swift_xcframework"]["distribution"] = copy.deepcopy(
            pending["distribution"]
        )
        after_alpha3 = copy.deepcopy(alpha3_parent)
        after_alpha3["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()

        for label, previous, current in (
            ("no-selector", no_selector, from_no_selector),
            ("alpha3-already-recorded", alpha3_parent, after_alpha3),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary) / "repository"
                _repository_with_parent_results(root, previous)
                with self.assertRaisesRegex(
                    proof_to_byte_finalizer.FinalizerError,
                    "only be introduced by the exact legacy",
                ):
                    proof_to_byte_finalizer.validate_release_publication_history(
                        root, current
                    )


if __name__ == "__main__":
    unittest.main()
