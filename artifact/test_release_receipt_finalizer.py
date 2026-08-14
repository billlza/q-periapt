#!/usr/bin/env python3
"""Direct cross-domain transaction tests for the results finalizer."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

import apple_alpha3_publication
import apple_publication_contract as apple_contract
import platform_alpha3_publication
import platform_alpha3_publication_contract as platform_contract
import publication_receipt_io
import release_receipt_finalizer as finalizer
from test_apple_publication_contract import (
    alpha2_receipt,
    alpha3_pending_receipt,
    alpha3_verified_receipt,
)
from test_platform_alpha3_publication_contract import (
    pending_receipt as platform_pending_receipt,
    verified_receipt as platform_verified_receipt,
)


def _bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


class ReleaseReceiptFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve() / "repository"
        self.root.mkdir(mode=0o755)
        self.target = self.root / "target"
        self.target.mkdir(mode=0o775)
        os.chmod(self.target, 0o775)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir(mode=0o755)
        self.results_path = self.artifact / "results.json"
        self.results_root = self.target / "release-publication-results"
        self.apple_root = self.target / "qperiapt-apple-publication-receipts"
        self.platform_root = self.target / "abi2-platform-publication-receipts"
        for receipt_root in (self.apple_root, self.platform_root):
            receipt_root.mkdir(mode=0o700)
            os.chmod(receipt_root, 0o700)
        self.receipt_index = 0

        for module, attribute, value in (
            (finalizer, "REPOSITORY_ROOT", self.root),
            (finalizer, "RESULTS_PATH", self.results_path),
            (finalizer, "RESULTS_CANDIDATE_ROOT", self.results_root),
            (
                apple_alpha3_publication,
                "APPLE_PUBLICATION_RECEIPT_ROOT",
                self.apple_root,
            ),
            (
                platform_alpha3_publication,
                "PLATFORM_PUBLICATION_RECEIPT_ROOT",
                self.platform_root,
            ),
        ):
            patcher = mock.patch.object(module, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _base_results(self) -> dict[str, object]:
        alpha2 = alpha2_receipt()
        return {
            "release_publications": {
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY: alpha2
            },
            "sentinel": {
                "must_remain": ["byte", "semantically", "unchanged"]
            },
            "swift_xcframework": {
                "distribution": copy.deepcopy(alpha2["distribution"]),
                "mode": "fixed unrelated field",
            },
        }

    def _write_results(self, document: dict[str, object]) -> str:
        self.results_path.write_bytes(_bytes(document))
        os.chmod(self.results_path, 0o644)
        return hashlib.sha256(self.results_path.read_bytes()).hexdigest()

    def _receipt(self, family: str, value: dict[str, object]) -> pathlib.Path:
        self.receipt_index += 1
        if family == "apple":
            root = self.apple_root
            leaf = apple_alpha3_publication.APPLE_PUBLICATION_RECEIPT_NAME
        else:
            root = self.platform_root
            leaf = platform_alpha3_publication.RECEIPT_NAME
        transaction = root / f"transaction.fixture-{self.receipt_index}"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        path = transaction / leaf
        path.write_bytes(_bytes(value))
        os.chmod(path, 0o600)
        return path

    def _pending_results(self, *, include_platform: bool) -> dict[str, object]:
        document = self._base_results()
        apple = alpha3_pending_receipt()
        document["release_publications"][
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        ] = apple
        document["swift_xcframework"]["distribution"] = copy.deepcopy(
            apple["distribution"]
        )
        if include_platform:
            document["release_publications"][
                platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
            ] = platform_pending_receipt()
        return document

    def test_apple_absent_pending_verified_and_read_only_idempotence(self) -> None:
        base = self._base_results()
        base_sha = self._write_results(base)
        pending_path = self._receipt("apple", alpha3_pending_receipt())
        output, _digest = finalizer.finalize_results(
            base_sha,
            apple_receipt_path=pending_path,
            platform_receipt_path=None,
        )
        pending_results = json.loads(output.read_text(encoding="ascii"))
        self.assertEqual(base["sentinel"], pending_results["sentinel"])
        self.assertEqual(
            base["release_publications"][
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            ],
            pending_results["release_publications"][
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            ],
        )
        self.assertEqual(
            alpha3_pending_receipt()["distribution"],
            pending_results["swift_xcframework"]["distribution"],
        )
        self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
        self.assertEqual(1, output.stat().st_nlink)

        pending_sha = self._write_results(pending_results)
        self.assertEqual(
            pending_sha,
            finalizer.verify_existing_receipts(
                pending_sha,
                apple_receipt_path=pending_path,
                platform_receipt_path=None,
            ),
        )
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError,
            "use read-only verify",
        ):
            finalizer.finalize_results(
                pending_sha,
                apple_receipt_path=pending_path,
                platform_receipt_path=None,
            )

        verified_path = self._receipt("apple", alpha3_verified_receipt())
        verified_output, _ = finalizer.finalize_results(
            pending_sha,
            apple_receipt_path=verified_path,
            platform_receipt_path=None,
        )
        verified_results = json.loads(
            verified_output.read_text(encoding="ascii")
        )
        self.assertEqual(
            apple_contract.APPLE_STATUS_VERIFIED,
            verified_results["release_publications"][
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
            ]["status"],
        )
        self.assertEqual(
            alpha3_verified_receipt()["distribution"],
            verified_results["swift_xcframework"]["distribution"],
        )

    def test_direct_verified_addition_and_candidate_drift_are_rejected(self) -> None:
        base_sha = self._write_results(self._base_results())
        verified_path = self._receipt("apple", alpha3_verified_receipt())
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError,
            "must first be recorded as pending",
        ):
            finalizer.finalize_results(
                base_sha,
                apple_receipt_path=verified_path,
                platform_receipt_path=None,
            )

        platform_verified_path = self._receipt(
            "platform",
            platform_verified_receipt(),
        )
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError,
            "must first be recorded as pending",
        ):
            finalizer.finalize_results(
                base_sha,
                apple_receipt_path=None,
                platform_receipt_path=platform_verified_path,
            )

        pending_results = self._pending_results(include_platform=False)
        pending_sha = self._write_results(pending_results)
        drifted = alpha3_pending_receipt()
        drifted["distribution"]["artifact_sha256"] = "a" * 64
        drifted["distribution"]["swiftpm_checksum"] = "a" * 64
        drifted_path = self._receipt("apple", drifted)
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError,
            "pending.*only remain unchanged",
        ):
            finalizer.finalize_results(
                pending_sha,
                apple_receipt_path=drifted_path,
                platform_receipt_path=None,
            )

    def test_one_or_two_leaves_and_partial_promotions_preserve_other_domain(
        self,
    ) -> None:
        base_sha = self._write_results(self._base_results())
        apple_pending_path = self._receipt("apple", alpha3_pending_receipt())
        platform_pending_path = self._receipt(
            "platform", platform_pending_receipt()
        )
        both_output, _ = finalizer.finalize_results(
            base_sha,
            apple_receipt_path=apple_pending_path,
            platform_receipt_path=platform_pending_path,
        )
        both_pending = json.loads(both_output.read_text(encoding="ascii"))
        self.assertEqual(
            platform_contract.PLATFORM_ALPHA3_STATUS_PENDING,
            both_pending["release_publications"][
                platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
            ]["status"],
        )
        both_sha = self._write_results(both_pending)

        apple_verified_path = self._receipt(
            "apple", alpha3_verified_receipt()
        )
        apple_only_output, _ = finalizer.finalize_results(
            both_sha,
            apple_receipt_path=apple_verified_path,
            platform_receipt_path=None,
        )
        apple_only = json.loads(apple_only_output.read_text(encoding="ascii"))
        self.assertEqual(
            both_pending["release_publications"][
                platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
            ],
            apple_only["release_publications"][
                platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
            ],
        )

        # Reset to the same two-pending parent and advance only platform.
        both_sha = self._write_results(both_pending)
        platform_verified_path = self._receipt(
            "platform", platform_verified_receipt()
        )
        platform_only_output, _ = finalizer.finalize_results(
            both_sha,
            apple_receipt_path=None,
            platform_receipt_path=platform_verified_path,
        )
        platform_only = json.loads(
            platform_only_output.read_text(encoding="ascii")
        )
        self.assertEqual(
            both_pending["release_publications"][
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
            ],
            platform_only["release_publications"][
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
            ],
        )
        self.assertEqual(
            platform_contract.PLATFORM_ALPHA3_STATUS_VERIFIED,
            platform_only["release_publications"][
                platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
            ]["status"],
        )

        both_sha = self._write_results(both_pending)
        both_verified_output, _ = finalizer.finalize_results(
            both_sha,
            apple_receipt_path=apple_verified_path,
            platform_receipt_path=platform_verified_path,
        )
        both_verified = json.loads(
            both_verified_output.read_text(encoding="ascii")
        )
        self.assertEqual(
            apple_contract.APPLE_STATUS_VERIFIED,
            both_verified["release_publications"][
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
            ]["status"],
        )
        self.assertEqual(
            platform_contract.PLATFORM_ALPHA3_STATUS_VERIFIED,
            both_verified["release_publications"][
                platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
            ]["status"],
        )

    def test_pins_fixed_receipt_roots_modes_hardlinks_and_end_resample(self) -> None:
        base_sha = self._write_results(self._base_results())
        pending_path = self._receipt("apple", alpha3_pending_receipt())
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError,
            "startup SHA-256 pin",
        ):
            finalizer.finalize_results(
                "f" * 64,
                apple_receipt_path=pending_path,
                platform_receipt_path=None,
            )

        outside = self.target / apple_alpha3_publication.APPLE_PUBLICATION_RECEIPT_NAME
        outside.write_bytes(pending_path.read_bytes())
        os.chmod(outside, 0o600)
        with self.assertRaises(publication_receipt_io.PublicationReceiptIOError):
            finalizer.finalize_results(
                base_sha,
                apple_receipt_path=outside,
                platform_receipt_path=None,
            )

        os.chmod(pending_path, 0o644)
        with self.assertRaises(publication_receipt_io.PublicationReceiptIOError):
            finalizer.finalize_results(
                base_sha,
                apple_receipt_path=pending_path,
                platform_receipt_path=None,
            )
        os.chmod(pending_path, 0o600)
        hardlink = pending_path.parent / "hardlink.json"
        os.link(pending_path, hardlink)
        with self.assertRaises(publication_receipt_io.PublicationReceiptIOError):
            finalizer.finalize_results(
                base_sha,
                apple_receipt_path=pending_path,
                platform_receipt_path=None,
            )
        hardlink.unlink()

        real_load = finalizer.load_current_results
        calls = 0

        def mutate_before_end(pin: str):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.results_path.write_bytes(b'{"changed":true}\n')
                os.chmod(self.results_path, 0o644)
            return real_load(pin)

        with mock.patch.object(
            finalizer,
            "load_current_results",
            side_effect=mutate_before_end,
        ):
            with self.assertRaisesRegex(
                finalizer.ReleaseReceiptFinalizerError,
                "startup SHA-256 pin",
            ):
                finalizer.finalize_results(
                    base_sha,
                    apple_receipt_path=pending_path,
                    platform_receipt_path=None,
                )
        if self.results_root.exists():
            self.assertEqual([], list(self.results_root.glob("*/results.json")))

    def test_output_fault_has_no_partial_candidate_and_later_run_recovers(self) -> None:
        base_sha = self._write_results(self._base_results())
        pending_path = self._receipt("apple", alpha3_pending_receipt())
        with mock.patch.object(
            publication_receipt_io,
            "_rename_noreplace",
            side_effect=publication_receipt_io.PublicationReceiptIOError(
                "injected output fault"
            ),
        ):
            with self.assertRaisesRegex(
                publication_receipt_io.PublicationReceiptIOError,
                "injected output fault",
            ):
                finalizer.finalize_results(
                    base_sha,
                    apple_receipt_path=pending_path,
                    platform_receipt_path=None,
                )
        self.assertEqual([], list(self.results_root.glob("*/results.json")))
        self.assertEqual(
            [], list(self.results_root.glob("*/.results.json.pending-*"))
        )

        output, _ = finalizer.finalize_results(
            base_sha,
            apple_receipt_path=pending_path,
            platform_receipt_path=None,
        )
        self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
