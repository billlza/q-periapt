#!/usr/bin/env python3
"""Real-Git history integration for the stable publication cohort."""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

import apple_publication_contract as apple_contract
import platform_publication_contract as platform_contract
import proof_to_byte_finalizer
from test_release_publication_contract import (
    pending_manifest_fixture,
    source_manifest_fixture,
    verified_manifest_fixture,
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
        cls.source = source_manifest_fixture(cls.legacy)
        cls.pending = pending_manifest_fixture(cls.legacy)
        cls.verified = verified_manifest_fixture(cls.legacy)

    def assert_history_transition(
        self, previous: dict[str, object], current: dict[str, object]
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, previous)
            proof_to_byte_finalizer.validate_release_publication_history(
                root, current
            )

    def assert_history_rejected(
        self,
        previous: dict[str, object],
        current: dict[str, object],
        pattern: str,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _repository_with_parent_results(root, previous)
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError, pattern
            ):
                proof_to_byte_finalizer.validate_release_publication_history(
                    root, current
                )

    def test_exact_legacy_selector_can_migrate_to_neutral_source(self) -> None:
        self.assert_history_transition(self.legacy, self.source)

    def test_source_can_advance_to_coordinated_pending(self) -> None:
        self.assert_history_transition(self.source, self.pending)

    def test_pending_can_advance_to_coordinated_verified(self) -> None:
        self.assert_history_transition(self.pending, self.verified)

    def test_source_cannot_skip_pending(self) -> None:
        self.assert_history_rejected(
            self.source,
            self.verified,
            "transition|pending|monotonic",
        )

    def test_pending_cannot_activate_stable_selector(self) -> None:
        activated = copy.deepcopy(self.pending)
        activated["swift_xcframework"] = copy.deepcopy(
            self.verified["swift_xcframework"]
        )
        self.assert_history_rejected(
            self.source,
            activated,
            "must be verified|cohort state",
        )

    def test_historical_receipt_cannot_change(self) -> None:
        changed = copy.deepcopy(self.pending)
        changed["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ]["boundary"] += " changed"
        self.assert_history_rejected(
            self.source,
            changed,
            "boundary differs|historical publication|frozen",
        )

    def test_cross_domain_source_identity_cannot_drift(self) -> None:
        changed = copy.deepcopy(self.pending)
        changed["release_publications"][
            platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY
        ]["observation"]["source"]["tag_tree"] = "a" * 40
        self.assert_history_rejected(
            self.source,
            changed,
            "source identities",
        )


if __name__ == "__main__":
    unittest.main()
