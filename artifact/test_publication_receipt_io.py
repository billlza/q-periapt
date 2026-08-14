#!/usr/bin/env python3
"""Fault and metadata tests for fixed-root publication receipt I/O."""

from __future__ import annotations

import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

import publication_receipt_io as receipt_io


class PublicationReceiptIOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = pathlib.Path(self.temporary.name).resolve() / "target"
        self.parent.mkdir(mode=0o775)
        os.chmod(self.parent, 0o775)
        self.safe_root = self.parent / "publication-receipts"

    def _private_input(self, payload: bytes) -> pathlib.Path:
        self.safe_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.input"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        path = transaction / "receipt.json"
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        return path

    def test_owned_0775_parent_bootstraps_private_transaction(self) -> None:
        path, digest = receipt_io.create_private_transaction_json(
            safe_root=self.safe_root,
            transaction_prefix="transaction.",
            expected_leaf="receipt.json",
            value={"kind": "fixture", "schema_version": 1},
            label="fixture receipt",
        )

        self.assertEqual(0o700, stat.S_IMODE(self.safe_root.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(1, path.stat().st_nlink)
        self.assertEqual(
            {"kind": "fixture", "schema_version": 1},
            json.loads(path.read_text(encoding="ascii")),
        )
        self.assertEqual(64, len(digest))

    def test_direct_child_creation_is_parent_synced_before_publication(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.fixture"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)

        self.assertEqual(
            transaction,
            receipt_io.verify_private_direct_child_and_sync_parent(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
            ),
        )
        with mock.patch.object(
            receipt_io.os,
            "fsync",
            side_effect=OSError("injected parent sync failure"),
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "cannot (?:sync|durably commit)",
            ):
                receipt_io.verify_private_direct_child_and_sync_parent(
                    safe_root=self.safe_root,
                    direct_child_name=transaction.name,
                    label="fixture transaction",
                )
        self.assertEqual([], list(transaction.glob("receipt.json")))

    def test_world_writable_parent_and_competing_roots_fail_closed(self) -> None:
        os.chmod(self.parent, 0o777)
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "non-world-writable",
        ):
            receipt_io.ensure_private_safe_root(
                self.safe_root,
                label="fixture root",
            )
        os.chmod(self.parent, 0o775)

        self.safe_root.write_bytes(b"competing file\n")
        with self.assertRaises(receipt_io.PublicationReceiptIOError):
            receipt_io.ensure_private_safe_root(
                self.safe_root,
                label="fixture root",
            )
        self.safe_root.unlink()

        outside = self.parent / "outside"
        outside.mkdir(mode=0o700)
        self.safe_root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(receipt_io.PublicationReceiptIOError):
            receipt_io.ensure_private_safe_root(
                self.safe_root,
                label="fixture root",
            )

    def test_atomic_race_never_replaces_competing_destination(self) -> None:
        real_rename = receipt_io._rename_noreplace

        def race(directory_fd: int, source: str, destination: str) -> None:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, b"competing complete output\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            real_rename(directory_fd, source, destination)

        with mock.patch.object(receipt_io, "_rename_noreplace", side_effect=race):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "already exists",
            ):
                receipt_io.create_private_transaction_json(
                    safe_root=self.safe_root,
                    transaction_prefix="transaction.",
                    expected_leaf="receipt.json",
                    value={"fixture": True},
                    label="fixture receipt",
                )

        outputs = list(self.safe_root.glob("*/receipt.json"))
        self.assertEqual(1, len(outputs))
        self.assertEqual(b"competing complete output\n", outputs[0].read_bytes())
        self.assertEqual([], list(self.safe_root.glob("*/.receipt.json.pending-*")))

    def test_prepublication_failure_leaves_no_final_or_staging_file(self) -> None:
        with mock.patch.object(
            receipt_io,
            "_rename_noreplace",
            side_effect=receipt_io.PublicationReceiptIOError("injected crash"),
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "injected crash",
            ):
                receipt_io.create_private_transaction_json(
                    safe_root=self.safe_root,
                    transaction_prefix="transaction.",
                    expected_leaf="receipt.json",
                    value={"fixture": True},
                    label="fixture receipt",
                )
        self.assertEqual([], list(self.safe_root.glob("*/receipt.json")))
        self.assertEqual([], list(self.safe_root.glob("*/.receipt.json.pending-*")))

    def test_write_file_sync_and_staging_close_faults_leave_no_leaf(self) -> None:
        fault_cases: list[tuple[str, object]] = []

        def fail_write(_descriptor: int, _payload: bytes) -> int:
            raise OSError("injected write failure")

        fault_cases.append(
            ("write", mock.patch.object(receipt_io.os, "write", fail_write))
        )

        real_fsync = receipt_io.os.fsync

        def fail_file_sync(descriptor: int) -> None:
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("injected file sync failure")
            real_fsync(descriptor)

        fault_cases.append(
            ("file-fsync", mock.patch.object(receipt_io.os, "fsync", fail_file_sync))
        )

        real_close = receipt_io.os.close
        close_fault_injected = False

        def fail_staging_close(descriptor: int) -> None:
            nonlocal close_fault_injected
            is_regular = False
            try:
                is_regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
            except OSError:
                pass
            real_close(descriptor)
            if is_regular and not close_fault_injected:
                close_fault_injected = True
                raise OSError("injected staging close failure")

        fault_cases.append(
            (
                "staging-close",
                mock.patch.object(receipt_io.os, "close", fail_staging_close),
            )
        )

        for label, fault in fault_cases:
            with self.subTest(fault=label), fault:
                with self.assertRaises(receipt_io.PublicationReceiptIOError):
                    receipt_io.create_private_transaction_json(
                        safe_root=self.safe_root,
                        transaction_prefix=f"transaction.{label}.",
                        expected_leaf="receipt.json",
                        value={"fixture": label},
                        label="fixture receipt",
                    )
            self.assertEqual([], list(self.safe_root.glob("*/receipt.json")))
            self.assertEqual(
                [], list(self.safe_root.glob("*/.receipt.json.pending-*"))
            )

    def test_parent_sync_failure_reports_an_already_committed_leaf(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        descriptor = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture receipt parent",
        )
        real_fsync = receipt_io.os.fsync

        def fail_parent_sync(target: int) -> None:
            if stat.S_ISDIR(os.fstat(target).st_mode):
                raise OSError("injected parent sync failure")
            real_fsync(target)

        try:
            with mock.patch.object(
                receipt_io.os,
                "fsync",
                side_effect=fail_parent_sync,
            ):
                with self.assertRaisesRegex(
                    receipt_io.PublicationReceiptCommittedError,
                    "atomically published",
                ):
                    receipt_io.write_private_bytes_noreplace_at(
                        descriptor,
                        "receipt.json",
                        b"complete bytes\n",
                        label="fixture receipt",
                    )
        finally:
            os.close(descriptor)
        self.assertEqual(
            b"complete bytes\n", (self.safe_root / "receipt.json").read_bytes()
        )
        self.assertEqual(
            [], list(self.safe_root.glob(".receipt.json.pending-*"))
        )

    def test_reader_keeps_transaction_parent_pinned_during_snapshot(self) -> None:
        path = self._private_input(b'{"kind":"original"}\n')
        original_parent = path.parent
        moved_parent = self.safe_root / "transaction.moved"
        real_consume = receipt_io.consume_regular_snapshot_at

        def swap_parent(*args: object, **kwargs: object):
            original_parent.rename(moved_parent)
            original_parent.mkdir(mode=0o700)
            os.chmod(original_parent, 0o700)
            replacement = original_parent / "receipt.json"
            replacement.write_bytes(b'{"kind":"replacement"}\n')
            os.chmod(replacement, 0o600)
            return real_consume(*args, **kwargs)

        with mock.patch.object(
            receipt_io,
            "consume_regular_snapshot_at",
            side_effect=swap_parent,
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "root/parent (?:identity )?changed",
            ):
                receipt_io.read_fixed_json_snapshot(
                    path,
                    safe_root=self.safe_root,
                    expected_leaf="receipt.json",
                    label="fixture receipt",
                    parent_depth=1,
                )

    def test_reader_rejects_safe_root_replacement_during_snapshot(self) -> None:
        path = self._private_input(b'{"kind":"original"}\n')
        moved_root = self.parent / "publication-receipts-moved"
        real_consume = receipt_io.consume_regular_snapshot_at

        def swap_root(*args: object, **kwargs: object):
            self.safe_root.rename(moved_root)
            self.safe_root.mkdir(mode=0o700)
            os.chmod(self.safe_root, 0o700)
            return real_consume(*args, **kwargs)

        with mock.patch.object(
            receipt_io,
            "consume_regular_snapshot_at",
            side_effect=swap_root,
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "root/parent (?:identity )?changed",
            ):
                receipt_io.read_fixed_json_snapshot(
                    path,
                    safe_root=self.safe_root,
                    expected_leaf="receipt.json",
                    label="fixture receipt",
                    parent_depth=1,
                )

    def test_writer_rejects_safe_root_replacement_while_fd_is_pinned(self) -> None:
        real_write = receipt_io.write_private_json_noreplace_at
        moved_root = self.parent / "publication-receipts-moved"

        def swap_root(*args: object, **kwargs: object) -> str:
            self.safe_root.rename(moved_root)
            self.safe_root.mkdir(mode=0o700)
            os.chmod(self.safe_root, 0o700)
            return real_write(*args, **kwargs)

        with mock.patch.object(
            receipt_io,
            "write_private_json_noreplace_at",
            side_effect=swap_root,
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "output root identity changed",
            ):
                receipt_io.create_private_transaction_json(
                    safe_root=self.safe_root,
                    transaction_prefix="transaction.",
                    expected_leaf="receipt.json",
                    value={"fixture": True},
                    label="fixture receipt",
                )
        self.assertEqual([], list(self.safe_root.glob("*/receipt.json")))
        self.assertEqual(1, len(list(moved_root.glob("*/receipt.json"))))

    def test_raw_bytes_writer_uses_the_same_atomic_boundary(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        descriptor = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            digest = receipt_io.write_private_bytes_noreplace_at(
                descriptor,
                "raw.json",
                b"exact raw bytes\n",
                label="fixture raw evidence",
                maximum=64,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(
            b"exact raw bytes\n",
            (self.safe_root / "raw.json").read_bytes(),
        )
        self.assertEqual(64, len(digest))

    def test_cleanup_failure_is_attached_to_primary_error(self) -> None:
        real_unlink = receipt_io.os.unlink

        def fail_staging_unlink(
            path: str | bytes,
            *,
            dir_fd: int | None = None,
        ) -> None:
            if dir_fd is not None and str(path).startswith(".receipt.json.pending-"):
                raise OSError("injected cleanup failure")
            real_unlink(path, dir_fd=dir_fd)

        with (
            mock.patch.object(
                receipt_io,
                "_rename_noreplace",
                side_effect=receipt_io.PublicationReceiptIOError(
                    "injected publication failure"
                ),
            ),
            mock.patch.object(receipt_io.os, "unlink", side_effect=fail_staging_unlink),
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "injected publication failure",
            ) as raised:
                receipt_io.create_private_transaction_json(
                    safe_root=self.safe_root,
                    transaction_prefix="transaction.",
                    expected_leaf="receipt.json",
                    value={"fixture": True},
                    label="fixture receipt",
                )
        self.assertTrue(
            any("cleanup failed" in note for note in raised.exception.__notes__)
        )

    def test_strict_reader_rejects_duplicates_size_mode_and_hardlinks(self) -> None:
        duplicate = self._private_input(b'{"kind":"one","kind":"two"}\n')
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "not strict JSON",
        ):
            receipt_io.read_fixed_json_snapshot(
                duplicate,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
            )

        duplicate.write_bytes(b'{"kind":"one"}\n')
        os.chmod(duplicate, 0o644)
        with self.assertRaises(receipt_io.PublicationReceiptIOError):
            receipt_io.read_fixed_json_snapshot(
                duplicate,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
            )
        os.chmod(duplicate, 0o600)

        alias = duplicate.parent / "hardlink.json"
        os.link(duplicate, alias)
        with self.assertRaises(receipt_io.PublicationReceiptIOError):
            receipt_io.read_fixed_json_snapshot(
                duplicate,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
            )
        alias.unlink()

        duplicate.write_bytes(b'{"kind":"one"}\n')
        with self.assertRaises(receipt_io.PublicationReceiptIOError):
            receipt_io.read_fixed_json_snapshot(
                duplicate,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
                maximum=4,
            )

    def test_reader_rejects_traversal_wrong_leaf_and_wrong_depth(self) -> None:
        path = self._private_input(b'{"kind":"one"}\n')
        for candidate, leaf, depth in (
            (path.parent / "../transaction.input/receipt.json", "receipt.json", 1),
            (path, "other.json", 1),
            (path, "receipt.json", 0),
        ):
            with self.subTest(candidate=candidate, leaf=leaf, depth=depth):
                with self.assertRaises(receipt_io.PublicationReceiptIOError):
                    receipt_io.read_fixed_json_snapshot(
                        candidate,
                        safe_root=self.safe_root,
                        expected_leaf=leaf,
                        label="fixture receipt",
                        parent_depth=depth,
                    )

    def test_invalid_parent_mode_after_open_does_not_leak_descriptors(self) -> None:
        path = self._private_input(b'{"kind":"one"}\n')
        os.chmod(path.parent, 0o755)
        before = len(list(pathlib.Path("/dev/fd").iterdir()))
        with self.assertRaises(receipt_io.PublicationReceiptIOError):
            receipt_io.read_fixed_json_snapshot(
                path,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
            )
        after = len(list(pathlib.Path("/dev/fd").iterdir()))
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
