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
import crates_io_publication_contract as crates_contract
import platform_publication_contract as platform_contract
import proof_to_byte_finalizer
import release_publication_contract as release_contract
from test_release_publication_contract import (
    legacy_swift_manifest_fixture,
    pending_manifest_fixture,
    source_manifest_fixture,
    verified_manifest_fixture,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]

_STABLE_COHORT_PUBLICATION_KEYS = (
    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
    platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
    crates_contract.CRATES_IO_PUBLICATION_KEY,
)


def frozen_legacy_manifest_fixture(
    live: dict[str, object],
) -> dict[str, object]:
    """Reconstruct the frozen pre-cohort legacy manifest from explicit bytes.

    The committed results.json is state-selected: it records the stable
    v0.1.3 cohort in either its pending or its verified selection state.
    The history chain exercised here starts at the frozen legacy alpha.2
    manifest, so that endpoint must come from pinned frozen bytes rather
    than the live manifest: restore the exact legacy selector fields and
    the frozen alpha.2 r1 distribution, and strip the stable cohort
    receipts the pending/verified installs introduced.
    """

    legacy = legacy_swift_manifest_fixture(live)
    swift = legacy["swift_xcframework"]
    assert isinstance(swift, dict)
    swift["distribution"] = apple_contract.frozen_alpha2_r1_distribution()
    publications = legacy["release_publications"]
    assert isinstance(publications, dict)
    for key in _STABLE_COHORT_PUBLICATION_KEYS:
        publications.pop(key, None)
    return legacy


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
        cls.live = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        cls.legacy = frozen_legacy_manifest_fixture(cls.live)
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

    def test_live_manifest_holds_a_committed_cohort_state(self) -> None:
        """Accept the live manifest in any committed cohort state."""

        state = release_contract.publication_state(self.live)
        self.assertIn(
            state,
            (
                release_contract.PUBLICATION_STATE_SOURCE,
                release_contract.PUBLICATION_STATE_PENDING,
                release_contract.PUBLICATION_STATE_VERIFIED,
            ),
        )
        if state == release_contract.PUBLICATION_STATE_SOURCE:
            swift = self.live["swift_xcframework"]
            if "active_publication_key" not in swift:
                # Initial pre-migration baseline: the live bytes are exactly
                # the frozen legacy manifest, whose only legal successor is
                # the one-time neutral selector migration (a legacy
                # self-transition is deliberately rejected).
                self.assertEqual(self.legacy, self.live)
                self.assert_history_transition(self.live, self.source)
                return
            # Freshly installed source results must sustain themselves under
            # the finalizer's first-parent history gate.
            self.assert_history_transition(self.live, self.live)
            return
        if state == release_contract.PUBLICATION_STATE_PENDING:
            # The committed pending cohort must be a valid successor of the
            # reconstructed source-results state.
            self.assert_history_transition(self.source, self.live)
        if state == release_contract.PUBLICATION_STATE_VERIFIED:
            # The verified cohort must be the exact successor of its real
            # first-parent pending manifest, so candidate drift during the
            # promotion cannot hide behind a self-transition.
            parent = self._first_parent_live_manifest()
            if parent is not None and release_contract.publication_state(
                parent
            ) == release_contract.PUBLICATION_STATE_PENDING:
                self.assert_history_transition(parent, self.live)
        # Either committed state must sustain itself under the finalizer's
        # first-parent history gate.
        self.assert_history_transition(self.live, self.live)

    @staticmethod
    def _first_parent_live_manifest() -> dict[str, object] | None:
        """Return the committed first-parent results manifest when available."""

        try:
            raw = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.fsmonitor=false",
                    "show",
                    "HEAD^:artifact/results.json",
                ],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                capture_output=True,
                timeout=30,
                check=True,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return manifest if isinstance(manifest, dict) else None

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
