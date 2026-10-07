#!/usr/bin/env python3
"""Unit tests for the neutral committed Rust package handoff loader."""

from __future__ import annotations

import copy
import hashlib
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import rust_package_handoff as handoff
from crates_io_publication_contract import (
    CRATE_PUBLICATION_TOPOLOGY,
    PRODUCT_VERSION,
)
from publication_receipt_io import canonical_json_bytes
from test_rust_publish_contract import (
    SOURCE_COMMIT,
    valid_rust_package_contract_transcript,
)


class RustPackageHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve() / "handoffs"
        self.root.mkdir(mode=0o700)
        self.transaction = self.root / ("transaction.1-" + "a" * 32)
        self.transaction.mkdir(mode=0o700)
        self.source = handoff.RustPackageHandoffSource(
            source_commit=SOURCE_COMMIT,
            source_tree="b" * 40,
            canonical_source_tree_sha256="c" * 64,
        )
        self.transcript = (
            "\n".join(valid_rust_package_contract_transcript()) + "\n"
        ).encode("utf-8")
        self._write_private(
            self.transaction / handoff.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
            self.transcript,
        )
        self.crate_records: list[dict[str, object]] = []
        for index, ((name, dependencies), leaf) in enumerate(
            zip(CRATE_PUBLICATION_TOPOLOGY, handoff.expected_crate_files()),
            start=1,
        ):
            payload = f"neutral handoff crate {index} {name}\n".encode("ascii")
            self._write_private(self.transaction / leaf, payload)
            self.crate_records.append(
                {
                    "crate_file": leaf,
                    "crate_sha256": hashlib.sha256(payload).hexdigest(),
                    "crate_size": len(payload),
                    "dependencies": list(dependencies),
                    "name": name,
                    "version": PRODUCT_VERSION,
                }
            )
        self.manifest_value: dict[str, object] = {
            "boundary": handoff.RUST_PACKAGE_HANDOFF_BOUNDARY,
            "crates": self.crate_records,
            "kind": handoff.RUST_PACKAGE_HANDOFF_KIND,
            "schema_version": handoff.RUST_PACKAGE_HANDOFF_SCHEMA_VERSION,
            "source": self.source.document(),
            "transcript": {
                "file": handoff.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                "sha256": hashlib.sha256(self.transcript).hexdigest(),
                "size": len(self.transcript),
            },
            "upload_attempted": False,
        }
        self.manifest_path = (
            self.transaction / handoff.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
        )
        self.manifest_sha256 = self._write_manifest(self.manifest_value)

    @staticmethod
    def _write_private(path: pathlib.Path, payload: bytes) -> None:
        path.write_bytes(payload)
        os.chmod(path, 0o600)

    def _write_manifest(self, value: object) -> str:
        payload = canonical_json_bytes(value)
        self._write_private(self.manifest_path, payload)
        return hashlib.sha256(payload).hexdigest()

    def load(self) -> handoff.RustPackageHandoffSnapshot:
        return handoff.load_rust_package_handoff_snapshot(
            self.manifest_path,
            self.manifest_sha256,
            self.source,
            handoff_root=self.root,
        )

    def test_loads_exact_twelve_leaf_transaction_and_parsed_receipt(self) -> None:
        snapshot = self.load()
        self.assertEqual(handoff.handoff_inventory(), snapshot.inventory)
        self.assertEqual(12, len(snapshot.inventory))
        self.assertEqual(self.manifest_sha256, snapshot.manifest.sha256)
        self.assertEqual(self.transcript, snapshot.transcript.data)
        self.assertEqual(SOURCE_COMMIT, snapshot.package_contract.source_commit)
        self.assertEqual(
            tuple(name for name, _dependencies in CRATE_PUBLICATION_TOPOLOGY),
            tuple(crate.name for crate in snapshot.crates),
        )
        self.assertEqual(
            snapshot.inventory,
            frozenset(path.name for path in self.transaction.iterdir()),
        )

    def test_requires_explicit_digest_fixed_path_and_exact_source(self) -> None:
        with self.assertRaisesRegex(
            handoff.RustPackageHandoffError,
            "explicit marker",
        ):
            handoff.load_rust_package_handoff_snapshot(
                self.manifest_path,
                "d" * 64,
                self.source,
                handoff_root=self.root,
            )
        with self.assertRaisesRegex(
            handoff.RustPackageHandoffError,
            "source identity differs",
        ):
            handoff.load_rust_package_handoff_snapshot(
                self.manifest_path,
                self.manifest_sha256,
                handoff.RustPackageHandoffSource(
                    source_commit=self.source.source_commit,
                    source_tree="e" * 40,
                    canonical_source_tree_sha256=(
                        self.source.canonical_source_tree_sha256
                    ),
                ),
                handoff_root=self.root,
            )
        outside = self.root.parent / handoff.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
        self._write_private(outside, self.manifest_path.read_bytes())
        with self.assertRaisesRegex(
            handoff.RustPackageHandoffError,
            "fixed transaction shape",
        ):
            handoff.load_rust_package_handoff_snapshot(
                outside,
                self.manifest_sha256,
                self.source,
                handoff_root=self.root,
            )

    def test_rejects_inventory_transcript_and_archive_mutation(self) -> None:
        extra = self.transaction / "unexpected"
        self._write_private(extra, b"extra")
        with self.assertRaisesRegex(
            handoff.RustPackageHandoffError,
            "entry set differs",
        ):
            self.load()
        extra.unlink()

        transcript_path = (
            self.transaction / handoff.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
        )
        transcript_path.write_bytes(self.transcript + b"changed\n")
        with self.assertRaisesRegex(
            handoff.RustPackageHandoffError,
            "transcript differs from its manifest",
        ):
            self.load()
        transcript_path.write_bytes(self.transcript)

        archive = self.transaction / handoff.expected_crate_files()[0]
        archive.write_bytes(b"replaced archive")
        with self.assertRaisesRegex(
            handoff.RustPackageHandoffError,
            "archive differs from its manifest",
        ):
            self.load()

    def test_rejects_topology_and_upload_attempted_manifest_drift(self) -> None:
        for label, mutate, message in (
            (
                "topology",
                lambda value: value["crates"].reverse(),
                "crate order differs",
            ),
            (
                "upload",
                lambda value: value.__setitem__("upload_attempted", True),
                "upload_attempted=false",
            ),
        ):
            with self.subTest(label=label):
                value = copy.deepcopy(self.manifest_value)
                mutate(value)
                digest = self._write_manifest(value)
                with self.assertRaisesRegex(
                    handoff.RustPackageHandoffError,
                    message,
                ):
                    handoff.load_rust_package_handoff_snapshot(
                        self.manifest_path,
                        digest,
                        self.source,
                        handoff_root=self.root,
                    )

    def test_resamples_manifest_after_all_payloads(self) -> None:
        original_reader = handoff.read_fixed_json_snapshot
        changed = copy.deepcopy(self.manifest_value)
        changed["upload_attempted"] = True
        changed_payload = canonical_json_bytes(changed)
        calls = 0

        def mutate_after_first_read(*args: object, **kwargs: object) -> object:
            nonlocal calls
            snapshot = original_reader(*args, **kwargs)
            calls += 1
            if calls == 1:
                self._write_private(self.manifest_path, changed_payload)
            return snapshot

        with (
            mock.patch.object(
                handoff,
                "read_fixed_json_snapshot",
                side_effect=mutate_after_first_read,
            ),
            self.assertRaisesRegex(
                handoff.RustPackageHandoffError,
                "changed while loading",
            ),
        ):
            self.load()


if __name__ == "__main__":
    unittest.main()
