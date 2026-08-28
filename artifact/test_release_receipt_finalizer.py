#!/usr/bin/env python3
"""Integration tests for the committed stable-cohort results finalizer."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import apple_publication_contract as apple_contract
import apple_stable_publication
import crates_io_publication
import crates_io_publication_contract as crates_contract
import platform_publication_contract as platform_contract
import platform_stable_publication
import release_publication_contract as aggregate
import release_receipt_finalizer as finalizer
from test_apple_publication_contract import (
    stable_pending_receipt,
    stable_verified_receipt,
)
from test_crates_io_publication_contract import receipt_fixture as crates_receipt
from test_platform_stable_publication_contract import (
    pending_receipt as platform_pending_receipt,
    verified_receipt as platform_verified_receipt,
)
from test_release_publication_contract import (
    _rebind_crates,
    _rebind_platform,
    neutral_selector_fixture,
    rebind_rust_publish_source,
    rebind_stable_current_source,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]


STABLE_COHORT_PUBLICATION_KEYS = (
    apple_contract.APPLE_V0_1_4_PUBLICATION_KEY,
    platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY,
    crates_contract.CRATES_IO_PUBLICATION_KEY,
    # The frozen published v0.1.3 leaves are permanent history in the live
    # manifest; the synthetic repository replays the state machine over
    # the pre-0.1.3 topology, so they are dropped alongside any active
    # v0.1.4 cohort state.
    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
    platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
    crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
)


def restore_source_publication_state(manifest: dict[str, object]) -> None:
    """Rewind any committed cohort state to the exact source projection.

    The live manifest carries the frozen published v0.1.3 cohort (its
    selector activated on apple_v0_1_3) and possibly an active v0.1.4
    cohort state, and these tests replay the complete source -> pending ->
    verified state machine from synthetic receipts.  The fixture therefore
    rewinds the live bytes to the pre-0.1.3 source projection: drop the
    stable-cohort leaves (frozen v0.1.3 history and any active v0.1.4
    state), and rebind the activated Apple selector to the frozen alpha.2
    legacy publication from the contract's own frozen distribution bytes
    rather than the state-dependent live selector.
    """

    publications = manifest["release_publications"]
    assert isinstance(publications, dict)
    for key in STABLE_COHORT_PUBLICATION_KEYS:
        publications.pop(key, None)
    swift = neutral_selector_fixture(manifest)
    active_key = swift["active_publication_key"]
    if active_key != apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY:
        if active_key not in (
            apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY,
        ):
            raise AssertionError(
                "live Apple selector names an unexpected publication key"
            )
        swift["active_publication_key"] = (
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        )
        swift["distribution"] = apple_contract.frozen_alpha2_r1_distribution()
    manifest["swift_xcframework"] = swift


class ReleaseReceiptFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir(mode=0o700)
        self.results = self.root / "artifact" / "results.json"
        self.results.parent.mkdir()
        legacy = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        self._write_results(legacy)
        self._git("init", "-q")
        self._git("add", ".")
        self._git("commit", "-qm", "source parent")
        self.source_commit = self._commit()
        self.source_digest = "8" * 64

        source = copy.deepcopy(legacy)
        source["provenance"]["snapshot_commit"] = self.source_commit
        source["proof_source_tree_sha256"] = self.source_digest
        source["rust_publish"] = rebind_rust_publish_source(
            source["rust_publish"],
            source_commit=self.source_commit,
            source_digest=self.source_digest,
        )
        rebind_stable_current_source(
            source,
            source_commit=self.source_commit,
            source_digest=self.source_digest,
        )
        restore_source_publication_state(source)
        self._write_results(source)
        self._git("add", "artifact/results.json")
        self._git("commit", "-qm", "install source results")
        self.results_commit = self._commit()
        self.results_tree = self._git_text(
            "rev-parse", "--verify", f"{self.results_commit}^{{tree}}"
        )

        self.apple_root = self.target / "apple-publication-receipts"
        self.platform_root = self.target / "platform-publication-receipts"
        self.crates_root = self.target / "qperiapt-crates-io-publication-receipts"
        self.candidate_root = self.target / "release-publication-results"
        for path in (self.apple_root, self.platform_root, self.crates_root):
            path.mkdir(mode=0o700)

        patches = (
            mock.patch.object(finalizer, "REPOSITORY_ROOT", self.root),
            mock.patch.object(finalizer, "RESULTS_PATH", self.results),
            mock.patch.object(
                finalizer, "RESULTS_CANDIDATE_ROOT", self.candidate_root
            ),
            mock.patch.object(
                apple_stable_publication,
                "APPLE_PUBLICATION_RECEIPT_ROOT",
                self.apple_root,
            ),
            mock.patch.object(
                platform_stable_publication,
                "PLATFORM_PUBLICATION_RECEIPT_ROOT",
                self.platform_root,
            ),
            mock.patch.object(
                crates_io_publication,
                "CRATES_IO_PUBLICATION_RECEIPT_ROOT",
                self.crates_root,
            ),
            mock.patch.object(finalizer, "validate_declared_currentness"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "user.name=Q-Periapt Test",
                "-c",
                "user.email=q-periapt-test@example.invalid",
                "-C",
                str(self.root),
                *arguments,
            ],
            check=True,
        )

    def _git_text(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["/usr/bin/git", "-C", str(self.root), *arguments],
            text=True,
        ).strip()

    def _commit(self) -> str:
        return self._git_text("rev-parse", "--verify", "HEAD^{commit}")

    def _write_results(self, value: dict[str, object]) -> str:
        data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self.results.write_bytes(data)
        self.results.chmod(0o644)
        return hashlib.sha256(data).hexdigest()

    def _current_sha256(self) -> str:
        return hashlib.sha256(self.results.read_bytes()).hexdigest()

    def _source_identity(self) -> dict[str, str]:
        return {
            "canonical_source_tree_sha256": self.source_digest,
            "source_parent_commit": self.source_commit,
            "tag_commit": self.results_commit,
            "tag_object": "9" * 40,
            "tag_tree": self.results_tree,
        }

    def _apple(self, *, verified: bool) -> dict[str, object]:
        receipt = stable_verified_receipt() if verified else stable_pending_receipt()
        source = self._source_identity()
        receipt["source"] = copy.deepcopy(source)
        receipt["distribution"]["source_commit"] = self.source_commit
        if verified:
            receipt["publication"]["source"] = {
                "tag_commit": self.results_commit,
                "tag_object": source["tag_object"],
            }
            receipt["publication"]["release_attestation"]["subjects"][0][
                "digest"
            ]["sha1"] = source["tag_object"]
        return receipt

    def _platform(self, *, verified: bool) -> dict[str, object]:
        receipt = platform_verified_receipt() if verified else platform_pending_receipt()
        source = self._source_identity()
        return _rebind_platform(receipt, source)

    def _crates(self) -> dict[str, object]:
        selected_rust = json.loads(self.results.read_text(encoding="utf-8"))[
            "rust_publish"
        ]
        return _rebind_crates(
            crates_receipt(10), self._source_identity(), selected_rust
        )

    @staticmethod
    def _receipt_path(
        root: pathlib.Path, leaf: str, value: dict[str, object], name: str
    ) -> pathlib.Path:
        transaction = root / name
        transaction.mkdir(mode=0o700)
        path = transaction / leaf
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def _receipt_paths(
        self, *, verified: bool
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path | None]:
        apple = self._receipt_path(
            self.apple_root,
            apple_stable_publication.APPLE_PUBLICATION_RECEIPT_NAME,
            self._apple(verified=verified),
            "verified" if verified else "pending",
        )
        platform = self._receipt_path(
            self.platform_root,
            platform_stable_publication.RECEIPT_NAME,
            self._platform(verified=verified),
            "verified" if verified else "pending",
        )
        crates = None
        if verified:
            crates = self._receipt_path(
                self.crates_root,
                crates_io_publication.CRATES_IO_PUBLICATION_RECEIPT_NAME,
                self._crates(),
                "verified",
            )
        return apple, platform, crates

    def _install_pending(self) -> tuple[str, str]:
        previous_sha256 = self._current_sha256()
        apple, platform, _ = self._receipt_paths(verified=False)
        pending, committed = finalizer.assemble_next_results(
            previous_sha256,
            apple_receipt_path=apple,
            platform_receipt_path=platform,
            crates_receipt_path=None,
        )
        self.assertEqual(self.results_commit, committed.commit)
        pending_sha256 = self._write_results(pending)
        self._git("add", "artifact/results.json")
        self._git("commit", "-qm", "record pending cohort")
        return self._commit(), pending_sha256

    def test_source_to_pending_requires_both_domains_and_keeps_selector(self) -> None:
        source_sha256 = self._current_sha256()
        before = json.loads(self.results.read_text(encoding="utf-8"))
        apple, platform, _ = self._receipt_paths(verified=False)
        pending, committed = finalizer.assemble_next_results(
            source_sha256,
            apple_receipt_path=apple,
            platform_receipt_path=platform,
            crates_receipt_path=None,
        )
        self.assertEqual(self.results_commit, committed.commit)
        self.assertEqual(
            aggregate.PUBLICATION_STATE_PENDING,
            aggregate.publication_state(pending),
        )
        self.assertEqual(
            before["swift_xcframework"], pending["swift_xcframework"]
        )
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "exactly Apple and platform"
        ):
            finalizer.assemble_next_results(
                source_sha256,
                apple_receipt_path=apple,
                platform_receipt_path=None,
                crates_receipt_path=None,
            )

    def test_pending_to_verified_requires_registry_and_switches_selector(self) -> None:
        self._install_pending()
        pending_sha256 = self._current_sha256()
        apple, platform, crates = self._receipt_paths(verified=True)
        verified, _committed = finalizer.assemble_next_results(
            pending_sha256,
            apple_receipt_path=apple,
            platform_receipt_path=platform,
            crates_receipt_path=crates,
        )
        self.assertEqual(
            aggregate.PUBLICATION_STATE_VERIFIED,
            aggregate.publication_state(verified),
        )
        self.assertEqual(
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY,
            verified["swift_xcframework"]["active_publication_key"],
        )
        self.assertEqual(
            verified["release_publications"][
                apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
            ]["distribution"],
            verified["swift_xcframework"]["distribution"],
        )

    def test_source_commit_tree_and_digest_mismatch_fail_closed(self) -> None:
        source_sha256 = self._current_sha256()
        apple, platform, _ = self._receipt_paths(verified=False)
        value = json.loads(platform.read_text(encoding="utf-8"))
        value["observation"]["source"]["tag_tree"] = "a" * 40
        platform.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        platform.chmod(0o600)
        with self.assertRaises(finalizer.ReleaseReceiptFinalizerError):
            finalizer.assemble_next_results(
                source_sha256,
                apple_receipt_path=apple,
                platform_receipt_path=platform,
                crates_receipt_path=None,
            )

    def test_current_results_must_be_clean_and_byte_identical_to_head(self) -> None:
        self.results.write_text("{}\n", encoding="utf-8")
        self.results.chmod(0o644)
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "clean committed checkout"
        ):
            finalizer.load_current_results(self._current_sha256())

        self._git("checkout", "--", "artifact/results.json")
        (self.root / "tracked.txt").write_text("new source\n", encoding="utf-8")
        self._git("add", "tracked.txt")
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "clean committed checkout"
        ):
            finalizer.load_current_results(self._current_sha256())

    def test_receipt_path_mode_hardlink_and_symlink_are_rejected(self) -> None:
        source_sha256 = self._current_sha256()
        apple, platform, _ = self._receipt_paths(verified=False)
        platform.chmod(0o644)
        with self.assertRaises(finalizer.PublicationReceiptIOError):
            finalizer._load_platform_receipt(platform)
        platform.chmod(0o600)

        second_link = platform.with_name("second-link.json")
        os.link(platform, second_link)
        with self.assertRaises(finalizer.PublicationReceiptIOError):
            finalizer._load_platform_receipt(platform)
        second_link.unlink()

        symlink_parent = self.platform_root / "symlink"
        symlink_parent.mkdir(mode=0o700)
        link = symlink_parent / platform_stable_publication.RECEIPT_NAME
        link.symlink_to(platform)
        with self.assertRaises(finalizer.PublicationReceiptIOError):
            finalizer._load_platform_receipt(link)
        self.assertTrue(apple.is_file())
        self.assertEqual(source_sha256, self._current_sha256())

    def test_finalize_emits_parent_binding_and_no_replace_candidate(self) -> None:
        source_sha256 = self._current_sha256()
        apple, platform, _ = self._receipt_paths(verified=False)
        path, digest, parent_commit, parent_sha256 = finalizer.finalize_results(
            source_sha256,
            apple_receipt_path=apple,
            platform_receipt_path=platform,
            crates_receipt_path=None,
        )
        self.assertTrue(path.is_file())
        self.assertEqual(self.results_commit, parent_commit)
        self.assertEqual(source_sha256, parent_sha256)
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_installed_pending_and_verified_transitions_are_rechecked(self) -> None:
        source_sha256 = self._current_sha256()
        parent_commit = self.results_commit
        pending_commit, pending_sha256 = self._install_pending()
        observed_commit, state = finalizer.verify_installed_results(
            pending_sha256,
            expected_parent_commit=parent_commit,
            expected_parent_results_sha256=source_sha256,
        )
        self.assertEqual(pending_commit, observed_commit)
        self.assertEqual(aggregate.PUBLICATION_STATE_PENDING, state)

        apple, platform, crates = self._receipt_paths(verified=True)
        verified, _ = finalizer.assemble_next_results(
            pending_sha256,
            apple_receipt_path=apple,
            platform_receipt_path=platform,
            crates_receipt_path=crates,
        )
        verified_sha256 = self._write_results(verified)
        self._git("add", "artifact/results.json")
        self._git("commit", "-qm", "record verified cohort")
        verified_commit = self._commit()
        observed_commit, state = finalizer.verify_installed_results(
            verified_sha256,
            expected_parent_commit=pending_commit,
            expected_parent_results_sha256=pending_sha256,
        )
        self.assertEqual(verified_commit, observed_commit)
        self.assertEqual(aggregate.PUBLICATION_STATE_VERIFIED, state)

        with self.assertRaises(finalizer.ReleaseReceiptFinalizerError):
            finalizer.verify_installed_results(
                verified_sha256,
                expected_parent_commit=self.source_commit,
                expected_parent_results_sha256=source_sha256,
            )

    def test_cli_markers_include_parent_and_installed_state(self) -> None:
        candidate = self.target / "candidate" / "results.json"
        args = argparse.Namespace(
            command="finalize",
            expected_results_sha256="a" * 64,
            apple_receipt=None,
            platform_receipt=None,
            crates_receipt=None,
        )
        with (
            mock.patch.object(
                finalizer,
                "finalize_results",
                return_value=(candidate, "b" * 64, "c" * 40, "d" * 64),
            ),
            mock.patch("builtins.print") as printer,
        ):
            finalizer.run(args)
        marker = printer.call_args.args[0]
        self.assertIn("parent_commit=" + "c" * 40, marker)
        self.assertIn("parent_sha256=" + "d" * 64, marker)


if __name__ == "__main__":
    unittest.main()
