#!/usr/bin/env python3
"""Fault and metadata tests for fixed-root publication receipt I/O."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from collections.abc import Iterator
from types import CodeType, FrameType
from typing import cast
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

    def _open_descriptor_count(self) -> int:
        for root in (pathlib.Path("/proc/self/fd"), pathlib.Path("/dev/fd")):
            if root.is_dir():
                return len(os.listdir(root))
        self.fail("POSIX descriptor inventory is unavailable")

    @contextlib.contextmanager
    def _interrupt_once_after_return(
        self,
        returned_code: CodeType,
        caller_code: CodeType,
        *,
        label: str,
    ) -> Iterator[None]:
        previous_trace = sys.gettrace()
        armed = False
        injected = False

        def trace(frame: FrameType, event: str, _argument: object) -> object:
            nonlocal armed, injected
            if event == "return" and frame.f_code is returned_code:
                armed = True
            elif armed and event == "line" and frame.f_code is caller_code:
                injected = True
                sys.settrace(None)
                raise KeyboardInterrupt(f"injected after {label} return")
            return trace

        sys.settrace(trace)
        try:
            yield
        finally:
            sys.settrace(previous_trace)
        self.assertTrue(injected, f"trace did not reach {label} return window")

    def test_descendant_sanitizer_uses_direct_scanner_visible_guard(self) -> None:
        tree = ast.parse(
            pathlib.Path(receipt_io.__file__).read_text(encoding="utf-8")
        )
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_normalized_descendant"
        )
        for call in (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_require"
        ):
            self.assertFalse(
                any(
                    isinstance(node, ast.Attribute)
                    and node.attr == "startswith"
                    for node in ast.walk(call)
                )
            )
        guards = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.op, ast.Not)
            and isinstance(node.test.operand, ast.Call)
            and isinstance(node.test.operand.func, ast.Attribute)
            and node.test.operand.func.attr == "startswith"
        ]
        self.assertEqual(1, len(guards))
        raised = guards[0].body[0]
        self.assertIsInstance(raised, ast.Raise)
        self.assertIsInstance(raised.exc, ast.Call)
        self.assertIsInstance(raised.exc.func, ast.Name)
        self.assertEqual("PublicationReceiptIOError", raised.exc.func.id)

    def test_committed_error_rejects_unknown_visibility_state(self) -> None:
        with self.assertRaisesRegex(ValueError, "visibility state is invalid"):
            receipt_io.PublicationReceiptCommittedError(
                "fixture invalid visibility",
                visibility=cast(receipt_io.PublicationVisibility, "unknown"),
            )

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

    def test_existing_child_syncs_safe_root_parent_then_child_parent(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.sync-ancestry"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        target_identity = (self.parent.stat().st_dev, self.parent.stat().st_ino)
        root_identity = (
            self.safe_root.stat().st_dev,
            self.safe_root.stat().st_ino,
        )
        synced: list[tuple[int, int]] = []
        real_fsync = receipt_io.os.fsync

        def record_fsync(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            synced.append((metadata.st_dev, metadata.st_ino))
            real_fsync(descriptor)

        with mock.patch.object(
            receipt_io.os,
            "fsync",
            side_effect=record_fsync,
        ):
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                receipt_io.sync_private_directory_parent(
                    handle,
                    label="fixture transaction",
                )
        self.assertIn(target_identity, synced)
        self.assertIn(root_identity, synced)
        self.assertLess(
            synced.index(target_identity),
            synced.index(root_identity),
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
        self.assertEqual([], list(self.safe_root.glob("transaction.*")))

    def test_write_and_file_sync_faults_leave_no_leaf(self) -> None:
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
            self.assertEqual(
                [], list(self.safe_root.glob(f"transaction.{label}.*"))
            )

    def test_failed_transaction_directory_cleanup_error_is_attached(
        self,
    ) -> None:
        real_rmdir = receipt_io.os.rmdir

        def fail_transaction_rmdir(
            path: str | bytes,
            *,
            dir_fd: int | None = None,
        ) -> None:
            if dir_fd is not None and str(path).startswith("transaction.cleanup-failure."):
                raise OSError("injected transaction cleanup failure")
            real_rmdir(path, dir_fd=dir_fd)

        with (
            mock.patch.object(
                receipt_io,
                "_rename_noreplace",
                side_effect=receipt_io.PublicationReceiptIOError(
                    "injected precommit publication failure"
                ),
            ),
            mock.patch.object(
                receipt_io.os,
                "rmdir",
                side_effect=fail_transaction_rmdir,
            ),
            self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "injected precommit publication failure",
            ) as caught,
        ):
            receipt_io.create_private_transaction_json(
                safe_root=self.safe_root,
                transaction_prefix="transaction.cleanup-failure.",
                expected_leaf="receipt.json",
                value={"fixture": True},
                label="fixture receipt",
            )

        self.assertTrue(
            any("cleanup failed" in note for note in caught.exception.__notes__)
        )
        retained = list(self.safe_root.glob("transaction.cleanup-failure.*"))
        self.assertEqual(1, len(retained))
        self.assertEqual([], list(retained[0].iterdir()))

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

    def test_reader_exact_parent_inventory_is_pinned_and_resampled(self) -> None:
        path = self._private_input(b'{"kind":"original"}\n')
        expected_entries = frozenset({"receipt.json"})
        observed_descriptors: list[int] = []
        real_inventory = receipt_io.verify_exact_directory_inventory_at

        def record_inventory(
            directory_fd: int,
            expected: frozenset[str],
            *,
            label: str,
        ) -> frozenset[str]:
            observed_descriptors.append(directory_fd)
            return real_inventory(
                directory_fd,
                expected,
                label=label,
            )

        with mock.patch.object(
            receipt_io,
            "verify_exact_directory_inventory_at",
            side_effect=record_inventory,
        ):
            snapshot = receipt_io.read_fixed_json_snapshot(
                path,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
                expected_parent_entries=expected_entries,
            )
        self.assertEqual(path, snapshot.file.path)
        self.assertEqual(2, len(observed_descriptors))
        self.assertEqual(1, len(set(observed_descriptors)))

        extra = path.parent / "unexpected.json"
        extra.write_bytes(b"{}\n")
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "entry set differs",
        ):
            receipt_io.read_fixed_json_snapshot(
                path,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
                expected_parent_entries=expected_entries,
            )
        extra.unlink()

        real_consume = receipt_io.consume_regular_snapshot_at

        def inject_after_snapshot(*args: object, **kwargs: object):
            digest = real_consume(*args, **kwargs)
            extra.write_bytes(b"{}\n")
            os.chmod(extra, 0o600)
            return digest

        with (
            mock.patch.object(
                receipt_io,
                "consume_regular_snapshot_at",
                side_effect=inject_after_snapshot,
            ),
            self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "entry set differs",
            ),
        ):
            receipt_io.read_fixed_json_snapshot(
                path,
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                label="fixture receipt",
                parent_depth=1,
                expected_parent_entries=expected_entries,
            )

    def test_direct_child_rejects_unsafe_leaf_without_opening_it(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        before = set(self.safe_root.iterdir())
        for leaf in ("", ".", "..", "nested/child", "nested\\child", "bad\x00leaf"):
            with self.subTest(leaf=leaf):
                with self.assertRaises(receipt_io.PublicationReceiptIOError):
                    receipt_io.verify_private_direct_child_and_sync_parent(
                        safe_root=self.safe_root,
                        direct_child_name=leaf,
                        label="fixture transaction",
                    )
                self.assertEqual(before, set(self.safe_root.iterdir()))

    def test_private_child_handle_rejects_swaps_and_create_collisions(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        existing = self.safe_root / "transaction.existing"
        existing.mkdir(mode=0o700)
        os.chmod(existing, 0o700)
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "already exists",
        ):
            with receipt_io.create_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=existing.name,
                label="fixture transaction",
            ):
                self.fail("existing transaction was replaced")
        self.assertTrue(existing.is_dir())

        created = self.safe_root / "transaction.created"
        with receipt_io.create_private_direct_child_handle(
            safe_root=self.safe_root,
            direct_child_name=created.name,
            label="fixture transaction",
        ) as handle:
            self.assertEqual(created, handle.path)
            self.assertEqual(0o700, stat.S_IMODE(os.fstat(handle.descriptor).st_mode))
        self.assertTrue(created.is_dir())

        moved = self.safe_root / "transaction.moved"
        replacement = self.safe_root / "transaction.existing"
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "identity changed while pinned",
        ):
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=replacement.name,
                label="fixture transaction",
            ):
                replacement.rename(moved)
                replacement.mkdir(mode=0o700)
                os.chmod(replacement, 0o700)

    def test_private_child_create_open_failure_removes_empty_entry(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        failed_name = "transaction.open-failure"
        real_open = receipt_io.os.open

        def fail_child_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == failed_name and dir_fd is not None:
                raise OSError("injected child open failure")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(
            receipt_io.os,
            "open",
            side_effect=fail_child_open,
        ):
            with self.assertRaises(
                receipt_io.PublicationReceiptIOError
            ) as caught:
                with receipt_io.create_private_direct_child_handle(
                    safe_root=self.safe_root,
                    direct_child_name=failed_name,
                    label="fixture transaction",
                ):
                    self.fail("failed child open unexpectedly yielded")
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertNotIn(str(self.parent), str(caught.exception))
        self.assertFalse((self.safe_root / failed_name).exists())

    def test_private_child_exit_revalidates_safe_root_mode(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.mode-change"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)

        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "safe root must be an owned mode-0700 directory",
        ):
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
            ):
                os.chmod(self.safe_root, 0o755)

    def test_root_open_fstat_oserror_is_domain_error_without_path(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.root-open-error"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_fstat = receipt_io.os.fstat
        injected = False

        def fail_once(descriptor: int) -> os.stat_result:
            nonlocal injected
            if not injected:
                injected = True
                raise OSError("injected root fstat failure")
            return real_fstat(descriptor)

        with mock.patch.object(receipt_io.os, "fstat", side_effect=fail_once):
            with self.assertRaises(
                receipt_io.PublicationReceiptIOError
            ) as caught:
                with receipt_io.open_private_direct_child_handle(
                    safe_root=self.safe_root,
                    direct_child_name=transaction.name,
                    label="fixture transaction",
                ):
                    self.fail("root fstat failure unexpectedly yielded")
        self.assertTrue(injected)
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertNotIn(str(self.parent), str(caught.exception))

    def test_unexpected_retained_parent_invariant_closes_all_descriptors(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        root_descriptor = os.open(self.safe_root, os.O_RDONLY)
        parent_descriptor = os.open(self.parent, os.O_RDONLY)
        with (
            mock.patch.object(
                receipt_io,
                "_open_or_create_private_safe_root",
                return_value=(
                    self.safe_root,
                    root_descriptor,
                    parent_descriptor,
                ),
            ),
            self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "unexpectedly retained",
            ),
        ):
            receipt_io.ensure_private_safe_root(
                self.safe_root,
                label="fixture root",
            )
        for descriptor in (root_descriptor, parent_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_handle_revalidation_oserror_is_domain_error_without_path(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.revalidation-error"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        with receipt_io.open_private_direct_child_handle(
            safe_root=self.safe_root,
            direct_child_name=transaction.name,
            label="fixture transaction",
        ) as handle:
            with (
                mock.patch.object(
                    receipt_io.os,
                    "fstat",
                    side_effect=OSError("injected revalidation failure"),
                ),
                self.assertRaises(
                    receipt_io.PublicationReceiptIOError
                ) as caught,
            ):
                receipt_io.verify_private_directory_handle_identity(
                    handle,
                    label="fixture transaction",
                )
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertNotIn(str(self.parent), str(caught.exception))

    def test_safe_root_exit_lstat_oserror_is_domain_error_without_path(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.root-lstat-error"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_lstat = receipt_io.pathlib.Path.lstat
        fail_exit = False

        def lstat(path: pathlib.Path) -> os.stat_result:
            if fail_exit and path == self.safe_root:
                raise OSError("injected safe-root lstat failure")
            return real_lstat(path)

        with (
            mock.patch.object(receipt_io.pathlib.Path, "lstat", lstat),
            self.assertRaises(
                receipt_io.PublicationReceiptIOError
            ) as caught,
        ):
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
            ):
                fail_exit = True
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertNotIn(str(self.parent), str(caught.exception))

    def test_prepared_commit_swap_before_visibility_leaves_no_receipt(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.precommit-swap"
        moved = self.safe_root / "transaction.precommit-swap-moved"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)

        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "identity changed while pinned",
        ):
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    {"fixture": True},
                    label="fixture receipt",
                ) as prepared:
                    transaction.rename(moved)
                    transaction.mkdir(mode=0o700)
                    os.chmod(transaction, 0o700)
                    prepared.commit_after_revalidation()
        self.assertFalse((transaction / "receipt.json").exists())
        self.assertFalse((moved / "receipt.json").exists())
        self.assertEqual([], list(moved.glob(".receipt.json.pending-*")))

    def test_prepared_immediate_noreplace_collision_stays_precommit(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.noreplace-collision"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        competing = b"competing receipt bytes\n"
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "already exists",
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    {"fixture": True},
                    label="fixture receipt",
                ) as prepared:
                    receipt = transaction / "receipt.json"
                    receipt.write_bytes(competing)
                    os.chmod(receipt, 0o600)
                    prepared.commit_after_revalidation()
        self.assertNotIsInstance(
            caught.exception,
            receipt_io.PublicationReceiptCommittedError,
        )
        self.assertEqual(competing, (transaction / "receipt.json").read_bytes())
        self.assertEqual([], list(transaction.glob(".receipt.json.pending-*")))

    def test_prepared_postrename_sync_failure_is_committed(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.committed-sync"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_fsync = receipt_io.os.fsync
        real_rename = receipt_io._rename_noreplace
        renamed = False
        run_descriptor = -1

        def rename(*args: object, **kwargs: object) -> None:
            nonlocal renamed
            real_rename(*args, **kwargs)
            renamed = True

        def fsync(descriptor: int) -> None:
            if renamed and descriptor == run_descriptor:
                raise OSError("injected post-rename sync failure")
            real_fsync(descriptor)

        with self.assertRaises(
            receipt_io.PublicationReceiptCommittedError
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                run_descriptor = handle.descriptor
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    {"fixture": True},
                    label="fixture receipt",
                ) as prepared:
                    with (
                        mock.patch.object(
                            receipt_io,
                            "_rename_noreplace",
                            side_effect=rename,
                        ),
                        mock.patch.object(
                            receipt_io.os,
                            "fsync",
                            side_effect=fsync,
                        ),
                    ):
                        prepared.commit_after_revalidation()
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(64, len(caught.exception.digest or ""))
        self.assertEqual(
            {"fixture": True},
            json.loads((transaction / "receipt.json").read_text(encoding="ascii")),
        )

    def test_prepared_postcommit_close_failure_is_committed(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.committed-close"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_close = receipt_io.os.close
        run_descriptor = -1
        committed = False

        def close(descriptor: int) -> None:
            if committed and descriptor == run_descriptor:
                real_close(descriptor)
                raise OSError("injected committed close failure")
            real_close(descriptor)

        with (
            mock.patch.object(receipt_io.os, "close", side_effect=close),
            self.assertRaises(receipt_io.PublicationReceiptCommittedError) as caught,
        ):
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                run_descriptor = handle.descriptor
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    {"fixture": True},
                    label="fixture receipt",
                ) as prepared:
                    prepared.commit_after_revalidation()
                    committed = True
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertTrue((transaction / "receipt.json").is_file())

    def test_prepared_held_file_close_fault_after_visibility_is_committed(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.held-close"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_close = receipt_io.os.close
        held_descriptor = -1

        def close(descriptor: int) -> None:
            real_close(descriptor)
            if descriptor == held_descriptor:
                raise OSError("injected held staging close failure")

        with receipt_io.open_private_direct_child_handle(
            safe_root=self.safe_root,
            direct_child_name=transaction.name,
            label="fixture transaction",
            sync_safe_root_parent=True,
        ) as handle:
            with receipt_io.prepare_private_json_noreplace_at(
                handle,
                "receipt.json",
                {"fixture": True},
                label="fixture receipt",
            ) as prepared:
                held_descriptor = prepared.descriptor
                with (
                    mock.patch.object(receipt_io.os, "close", side_effect=close),
                    self.assertRaises(
                        receipt_io.PublicationReceiptCommittedError
                    ) as caught,
                ):
                    prepared.commit_after_revalidation()
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertTrue((transaction / "receipt.json").is_file())
        with self.assertRaises(OSError):
            os.fstat(held_descriptor)

    def test_prepared_pre_effect_close_interrupt_is_not_retried(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.pre-effect-held-close"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        baseline_descriptors = self._open_descriptor_count()
        real_close = receipt_io.os.close
        held_descriptor = -1
        interrupted = False

        def close(descriptor: int) -> None:
            nonlocal interrupted
            if descriptor == held_descriptor and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("injected pre-effect close interruption")
            real_close(descriptor)

        with receipt_io.open_private_direct_child_handle(
            safe_root=self.safe_root,
            direct_child_name=transaction.name,
            label="fixture transaction",
            sync_safe_root_parent=True,
        ) as handle:
            with receipt_io.prepare_private_json_noreplace_at(
                handle,
                "receipt.json",
                {"fixture": True},
                label="fixture receipt",
            ) as prepared:
                held_descriptor = prepared.descriptor
                with (
                    mock.patch.object(receipt_io.os, "close", side_effect=close),
                    self.assertRaises(
                        receipt_io.PublicationReceiptCommittedError
                    ) as caught,
                ):
                    prepared.commit_after_revalidation()

        self.assertTrue(interrupted)
        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertTrue((transaction / "receipt.json").is_file())
        os.fstat(held_descriptor)
        real_close(held_descriptor)
        self.assertEqual(baseline_descriptors, self._open_descriptor_count())

    def test_prepared_precommit_close_fault_preserves_primary_error(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.precommit-close"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_close = receipt_io.os.close
        held_descriptor = -1

        def close(descriptor: int) -> None:
            real_close(descriptor)
            if descriptor == held_descriptor:
                raise OSError("injected precommit staging close failure")

        with mock.patch.object(receipt_io.os, "close", side_effect=close):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptIOError,
                "injected precommit publication failure",
            ) as caught:
                with receipt_io.open_private_direct_child_handle(
                    safe_root=self.safe_root,
                    direct_child_name=transaction.name,
                    label="fixture transaction",
                    sync_safe_root_parent=True,
                ) as handle:
                    with receipt_io.prepare_private_json_noreplace_at(
                        handle,
                        "receipt.json",
                        {"fixture": True},
                        label="fixture receipt",
                    ) as prepared:
                        held_descriptor = prepared.descriptor
                        with mock.patch.object(
                            receipt_io,
                            "_rename_noreplace",
                            side_effect=receipt_io.PublicationReceiptIOError(
                                "injected precommit publication failure"
                            ),
                        ):
                            prepared.commit_after_revalidation()
        self.assertTrue(
            any("staging cleanup failed" in note for note in caught.exception.__notes__)
        )
        self.assertFalse((transaction / "receipt.json").exists())
        self.assertEqual([], list(transaction.glob(".receipt.json.pending-*")))
        with self.assertRaises(OSError):
            os.fstat(held_descriptor)

    def test_prepared_rename_hook_swap_reports_committed_identity_failure(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.rename-swap"
        moved = self.safe_root / "transaction.rename-swap-moved"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        real_rename = receipt_io._rename_noreplace

        def rename_and_swap(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            transaction.rename(moved)
            transaction.mkdir(mode=0o700)
            os.chmod(transaction, 0o700)

        with self.assertRaises(
            receipt_io.PublicationReceiptCommittedError
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    {"fixture": True},
                    label="fixture receipt",
                ) as prepared:
                    with mock.patch.object(
                        receipt_io,
                        "_rename_noreplace",
                        side_effect=rename_and_swap,
                    ):
                        prepared.commit_after_revalidation()
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertFalse((transaction / "receipt.json").exists())
        self.assertTrue((moved / "receipt.json").is_file())

    def test_prepared_rejects_same_bytes_competitor_after_rename(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.same-bytes-competitor"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        value = {"fixture": True}
        payload = receipt_io.canonical_json_bytes(value)
        real_rename = receipt_io._rename_noreplace
        held_descriptor = -1

        def replace_after_rename(
            directory_fd: int,
            source_leaf: str,
            destination_leaf: str,
        ) -> None:
            real_rename(directory_fd, source_leaf, destination_leaf)
            held_before_unlink = os.fstat(held_descriptor)
            self.assertEqual(1, held_before_unlink.st_nlink)
            os.unlink(destination_leaf, dir_fd=directory_fd)
            self.assertEqual(0, os.fstat(held_descriptor).st_nlink)
            descriptor = os.open(
                destination_leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.assertNotEqual(
                held_before_unlink.st_ino,
                os.stat(
                    destination_leaf,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                ).st_ino,
            )

        with self.assertRaises(
            receipt_io.PublicationReceiptCommittedError
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    value,
                    label="fixture receipt",
                ) as prepared:
                    held_descriptor = prepared.descriptor
                    with mock.patch.object(
                        receipt_io,
                        "_rename_noreplace",
                        side_effect=replace_after_rename,
                    ):
                        prepared.commit_after_revalidation()
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(payload, (transaction / "receipt.json").read_bytes())
        with self.assertRaises(OSError):
            os.fstat(held_descriptor)

    def test_prepared_rename_interrupt_recovers_committed_state(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.rename-interrupt"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        value = {"fixture": True}
        payload = receipt_io.canonical_json_bytes(value)
        real_rename = receipt_io._rename_noreplace

        def rename_then_interrupt(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            raise KeyboardInterrupt("injected visibility interruption")

        with self.assertRaises(
            receipt_io.PublicationReceiptCommittedError
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    value,
                    label="fixture receipt",
                ) as prepared:
                    with mock.patch.object(
                        receipt_io,
                        "_rename_noreplace",
                        side_effect=rename_then_interrupt,
                    ):
                        prepared.commit_after_revalidation()
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), caught.exception.digest)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(payload, (transaction / "receipt.json").read_bytes())
        self.assertEqual([], list(transaction.glob(".receipt.json.pending-*")))

    def test_prepared_after_return_interrupts_are_structured_committed(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        value = {"fixture": "after-return"}
        payload = receipt_io.canonical_json_bytes(value)
        digest = hashlib.sha256(payload).hexdigest()
        real_rename = receipt_io._rename_noreplace

        for scenario in ("rename", "classification", "helper"):
            with self.subTest(window=f"{scenario}-return"):
                transaction = self.safe_root / f"transaction.{scenario}-return"
                transaction.mkdir(mode=0o700)
                os.chmod(transaction, 0o700)
                held_descriptor = -1

                if scenario == "rename":
                    rename_patch = contextlib.nullcontext()
                    returned_code = real_rename.__code__
                    caller_code = (
                        receipt_io._publish_private_file_noreplace_at.__code__
                    )
                elif scenario == "classification":

                    def rename_then_interrupt(
                        *args: object,
                        **kwargs: object,
                    ) -> None:
                        real_rename(*args, **kwargs)
                        raise SystemExit("injected first visibility interruption")

                    rename_patch = mock.patch.object(
                        receipt_io,
                        "_rename_noreplace",
                        side_effect=rename_then_interrupt,
                    )
                    returned_code = (
                        receipt_io._classify_interrupted_visibility_conservatively
                        .__code__
                    )
                    caller_code = (
                        receipt_io._raise_for_private_file_publication_visibility
                        .__code__
                    )
                else:
                    rename_patch = contextlib.nullcontext()
                    returned_code = (
                        receipt_io._publish_private_file_noreplace_at.__code__
                    )
                    caller_code = (
                        receipt_io.PreparedPrivateJsonPublication
                        ._commit_after_revalidation.__code__
                    )

                with self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught:
                    with receipt_io.open_private_direct_child_handle(
                        safe_root=self.safe_root,
                        direct_child_name=transaction.name,
                        label="fixture transaction",
                        sync_safe_root_parent=True,
                    ) as handle:
                        with receipt_io.prepare_private_json_noreplace_at(
                            handle,
                            "receipt.json",
                            value,
                            label="fixture receipt",
                        ) as prepared:
                            held_descriptor = prepared.descriptor
                            with (
                                rename_patch,
                                self._interrupt_once_after_return(
                                    returned_code,
                                    caller_code,
                                    label=scenario,
                                ),
                            ):
                                prepared.commit_after_revalidation()

                self.assertEqual("committed", caught.exception.visibility)
                self.assertEqual("receipt.json", caught.exception.leaf)
                self.assertEqual(digest, caught.exception.digest)
                self.assertIsInstance(
                    caught.exception.__cause__,
                    KeyboardInterrupt,
                )
                self.assertEqual(
                    payload,
                    (transaction / "receipt.json").read_bytes(),
                )
                self.assertEqual(
                    [],
                    list(transaction.glob(".receipt.json.pending-*")),
                )
                with self.assertRaises(OSError):
                    os.fstat(held_descriptor)

    def test_prepared_recovery_inspection_fault_preserves_indeterminate(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.recovery-fault"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        value = {"fixture": True}
        payload = receipt_io.canonical_json_bytes(value)
        real_rename = receipt_io._rename_noreplace
        real_consume = receipt_io.consume_regular_snapshot_at
        consume_calls = 0

        def rename_then_interrupt(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            raise KeyboardInterrupt("injected visibility interruption")

        def fail_recovery_inspection(*args: object, **kwargs: object):
            nonlocal consume_calls
            consume_calls += 1
            if consume_calls == 2:
                raise receipt_io.EvidenceIOError(
                    "injected recovery inspection failure"
                )
            return real_consume(*args, **kwargs)

        with self.assertRaises(
            receipt_io.PublicationReceiptCommittedError
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    value,
                    label="fixture receipt",
                ) as prepared:
                    with (
                        mock.patch.object(
                            receipt_io,
                            "_rename_noreplace",
                            side_effect=rename_then_interrupt,
                        ),
                        mock.patch.object(
                            receipt_io,
                            "consume_regular_snapshot_at",
                            side_effect=fail_recovery_inspection,
                        ),
                    ):
                        prepared.commit_after_revalidation()
        self.assertEqual("indeterminate", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), caught.exception.digest)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertIn("visibility indeterminate", str(caught.exception))
        self.assertEqual(payload, (transaction / "receipt.json").read_bytes())
        self.assertEqual([], list(transaction.glob(".receipt.json.pending-*")))

    def test_prepared_second_interrupt_during_classification_is_preserved(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        transaction = self.safe_root / "transaction.second-interrupt"
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        value = {"fixture": True}
        real_rename = receipt_io._rename_noreplace

        def rename_then_interrupt(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            raise KeyboardInterrupt("injected visibility interruption")

        with self.assertRaises(
            receipt_io.PublicationReceiptCommittedError
        ) as caught:
            with receipt_io.open_private_direct_child_handle(
                safe_root=self.safe_root,
                direct_child_name=transaction.name,
                label="fixture transaction",
                sync_safe_root_parent=True,
            ) as handle:
                with receipt_io.prepare_private_json_noreplace_at(
                    handle,
                    "receipt.json",
                    value,
                    label="fixture receipt",
                ) as prepared:
                    with (
                        mock.patch.object(
                            receipt_io,
                            "_rename_noreplace",
                            side_effect=rename_then_interrupt,
                        ),
                        mock.patch.object(
                            receipt_io,
                            "_classify_interrupted_visibility_at",
                            side_effect=SystemExit(
                                "injected classification interruption"
                            ),
                        ),
                    ):
                        prepared.commit_after_revalidation()
        self.assertEqual("indeterminate", caught.exception.visibility)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertTrue((transaction / "receipt.json").is_file())

    def test_atomic_bytes_writer_rejects_same_bytes_rename_competitor(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        payload = b"exact fixture bytes\n"
        real_rename = receipt_io._rename_noreplace
        real_open = receipt_io.os.open
        held_descriptor = -1

        def open_and_track(
            path: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal held_descriptor
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if (
                isinstance(path, str)
                and path.startswith(".raw.json.pending-")
                and (flags & os.O_RDWR) == os.O_RDWR
            ):
                held_descriptor = descriptor
            return descriptor

        def replace_after_rename(
            directory_fd: int,
            source_leaf: str,
            destination_leaf: str,
        ) -> None:
            real_rename(directory_fd, source_leaf, destination_leaf)
            held_before_unlink = os.fstat(held_descriptor)
            self.assertEqual(1, held_before_unlink.st_nlink)
            os.unlink(destination_leaf, dir_fd=directory_fd)
            self.assertEqual(0, os.fstat(held_descriptor).st_nlink)
            descriptor = os.open(
                destination_leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.assertNotEqual(
                held_before_unlink.st_ino,
                os.stat(
                    destination_leaf,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                ).st_ino,
            )

        descriptor = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            with (
                mock.patch.object(
                    receipt_io,
                    "_rename_noreplace",
                    side_effect=replace_after_rename,
                ),
                mock.patch.object(
                    receipt_io.os,
                    "open",
                    side_effect=open_and_track,
                ),
                self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught,
            ):
                receipt_io.write_private_bytes_noreplace_at(
                    descriptor,
                    "raw.json",
                    payload,
                    label="fixture raw evidence",
                    maximum=64,
                )
        finally:
            os.close(descriptor)
        self.assertEqual("raw.json", caught.exception.leaf)
        self.assertEqual(payload, (self.safe_root / "raw.json").read_bytes())
        with self.assertRaises(OSError):
            os.fstat(held_descriptor)

    def test_atomic_bytes_held_file_close_fault_is_committed(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        payload = b"exact held close bytes\n"
        real_open = receipt_io.os.open
        real_close = receipt_io.os.close
        held_descriptor = -1

        def open_and_track(
            path: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal held_descriptor
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if (
                isinstance(path, str)
                and path.startswith(".raw.json.pending-")
                and (flags & os.O_RDWR) == os.O_RDWR
            ):
                held_descriptor = descriptor
            return descriptor

        def close(descriptor: int) -> None:
            real_close(descriptor)
            if descriptor == held_descriptor:
                raise OSError("injected held staging close failure")

        directory_fd = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            with (
                mock.patch.object(
                    receipt_io.os,
                    "open",
                    side_effect=open_and_track,
                ),
                mock.patch.object(receipt_io.os, "close", side_effect=close),
                self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught,
            ):
                receipt_io.write_private_bytes_noreplace_at(
                    directory_fd,
                    "raw.json",
                    payload,
                    label="fixture raw evidence",
                    maximum=64,
                )
        finally:
            os.close(directory_fd)
        self.assertEqual("raw.json", caught.exception.leaf)
        self.assertEqual(payload, (self.safe_root / "raw.json").read_bytes())
        with self.assertRaises(OSError):
            os.fstat(held_descriptor)

    def test_atomic_bytes_pre_effect_close_interrupt_is_not_retried(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        payload = b"exact pre-effect close bytes\n"
        baseline_descriptors = self._open_descriptor_count()
        real_open = receipt_io.os.open
        real_close = receipt_io.os.close
        held_descriptor = -1
        interrupted = False

        def open_and_track(
            path: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal held_descriptor
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if (
                isinstance(path, str)
                and path.startswith(".raw.json.pending-")
                and (flags & os.O_RDWR) == os.O_RDWR
            ):
                held_descriptor = descriptor
            return descriptor

        def close(descriptor: int) -> None:
            nonlocal interrupted
            if descriptor == held_descriptor and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("injected pre-effect close interruption")
            real_close(descriptor)

        directory_fd = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            with (
                mock.patch.object(
                    receipt_io.os,
                    "open",
                    side_effect=open_and_track,
                ),
                mock.patch.object(receipt_io.os, "close", side_effect=close),
                self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught,
            ):
                receipt_io.write_private_bytes_noreplace_at(
                    directory_fd,
                    "raw.json",
                    payload,
                    label="fixture raw evidence",
                    maximum=64,
                )
        finally:
            os.close(directory_fd)

        self.assertTrue(interrupted)
        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("raw.json", caught.exception.leaf)
        self.assertEqual(payload, (self.safe_root / "raw.json").read_bytes())
        os.fstat(held_descriptor)
        real_close(held_descriptor)
        self.assertEqual(baseline_descriptors, self._open_descriptor_count())

    def test_atomic_bytes_rename_interrupt_recovers_committed_state(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        payload = b"exact interrupt fixture bytes\n"
        real_rename = receipt_io._rename_noreplace

        def rename_then_interrupt(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            raise KeyboardInterrupt("injected visibility interruption")

        descriptor = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            with (
                mock.patch.object(
                    receipt_io,
                    "_rename_noreplace",
                    side_effect=rename_then_interrupt,
                ),
                self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught,
            ):
                receipt_io.write_private_bytes_noreplace_at(
                    descriptor,
                    "raw.json",
                    payload,
                    label="fixture raw evidence",
                    maximum=64,
                )
        finally:
            os.close(descriptor)
        self.assertEqual("raw.json", caught.exception.leaf)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), caught.exception.digest)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(payload, (self.safe_root / "raw.json").read_bytes())
        self.assertEqual([], list(self.safe_root.glob(".raw.json.pending-*")))

    def test_atomic_bytes_after_return_interrupts_are_structured_committed(
        self,
    ) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        payload = b"exact after-return fixture bytes\n"
        digest = hashlib.sha256(payload).hexdigest()
        real_rename = receipt_io._rename_noreplace
        real_open = receipt_io.os.open
        directory_fd = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            for scenario in ("rename", "classification", "helper"):
                with self.subTest(window=f"{scenario}-return"):
                    leaf = f"raw-{scenario}.json"
                    held_descriptor = -1

                    def open_and_track(
                        path: str | bytes,
                        flags: int,
                        mode: int = 0o777,
                        *,
                        dir_fd: int | None = None,
                    ) -> int:
                        nonlocal held_descriptor
                        opened = real_open(path, flags, mode, dir_fd=dir_fd)
                        if (
                            isinstance(path, str)
                            and path.startswith(f".{leaf}.pending-")
                            and (flags & os.O_RDWR) == os.O_RDWR
                        ):
                            held_descriptor = opened
                        return opened

                    if scenario == "rename":
                        rename_patch = contextlib.nullcontext()
                        returned_code = real_rename.__code__
                        caller_code = (
                            receipt_io._publish_private_file_noreplace_at.__code__
                        )
                    elif scenario == "classification":

                        def rename_then_interrupt(
                            *args: object,
                            **kwargs: object,
                        ) -> None:
                            real_rename(*args, **kwargs)
                            raise SystemExit(
                                "injected first visibility interruption"
                            )

                        rename_patch = mock.patch.object(
                            receipt_io,
                            "_rename_noreplace",
                            side_effect=rename_then_interrupt,
                        )
                        returned_code = (
                            receipt_io
                            ._classify_interrupted_visibility_conservatively.__code__
                        )
                        caller_code = (
                            receipt_io
                            ._raise_for_private_file_publication_visibility.__code__
                        )
                    else:
                        rename_patch = contextlib.nullcontext()
                        returned_code = (
                            receipt_io._publish_private_file_noreplace_at.__code__
                        )
                        caller_code = (
                            receipt_io._write_private_bytes_noreplace_at.__code__
                        )

                    with (
                        self.assertRaises(
                            receipt_io.PublicationReceiptCommittedError
                        ) as caught,
                        rename_patch,
                        mock.patch.object(
                            receipt_io.os,
                            "open",
                            side_effect=open_and_track,
                        ),
                        self._interrupt_once_after_return(
                            returned_code,
                            caller_code,
                            label=scenario,
                        ),
                    ):
                        receipt_io.write_private_bytes_noreplace_at(
                            directory_fd,
                            leaf,
                            payload,
                            label="fixture raw evidence",
                            maximum=64,
                        )

                    self.assertEqual("committed", caught.exception.visibility)
                    self.assertEqual(leaf, caught.exception.leaf)
                    self.assertEqual(digest, caught.exception.digest)
                    self.assertIsInstance(
                        caught.exception.__cause__,
                        KeyboardInterrupt,
                    )
                    self.assertEqual(payload, (self.safe_root / leaf).read_bytes())
                    self.assertEqual(
                        [],
                        list(self.safe_root.glob(f".{leaf}.pending-*")),
                    )
                    with self.assertRaises(OSError):
                        os.fstat(held_descriptor)
        finally:
            os.close(directory_fd)

    def test_atomic_bytes_recovery_inspection_fault_is_indeterminate(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        payload = b"exact recovery fault bytes\n"
        real_rename = receipt_io._rename_noreplace

        def rename_then_interrupt(*args: object, **kwargs: object) -> None:
            real_rename(*args, **kwargs)
            raise KeyboardInterrupt("injected visibility interruption")

        descriptor = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture bytes root",
        )
        try:
            with (
                mock.patch.object(
                    receipt_io,
                    "_rename_noreplace",
                    side_effect=rename_then_interrupt,
                ),
                mock.patch.object(
                    receipt_io,
                    "_classify_interrupted_visibility_at",
                    side_effect=receipt_io.EvidenceIOError(
                        "injected recovery inspection failure"
                    ),
                ),
                self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught,
            ):
                receipt_io.write_private_bytes_noreplace_at(
                    descriptor,
                    "raw.json",
                    payload,
                    label="fixture raw evidence",
                    maximum=64,
                )
        finally:
            os.close(descriptor)
        self.assertEqual("indeterminate", caught.exception.visibility)
        self.assertEqual("raw.json", caught.exception.leaf)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), caught.exception.digest)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(payload, (self.safe_root / "raw.json").read_bytes())
        self.assertEqual([], list(self.safe_root.glob(".raw.json.pending-*")))

    def test_writer_rejects_safe_root_replacement_while_fd_is_pinned(self) -> None:
        real_write = receipt_io._write_private_bytes_noreplace_at
        moved_root = self.parent / "publication-receipts-moved"

        def swap_root(*args: object, **kwargs: object) -> str:
            self.safe_root.rename(moved_root)
            self.safe_root.mkdir(mode=0o700)
            os.chmod(self.safe_root, 0o700)
            return real_write(*args, **kwargs)

        with mock.patch.object(
            receipt_io,
            "_write_private_bytes_noreplace_at",
            side_effect=swap_root,
        ):
            with self.assertRaisesRegex(
                receipt_io.PublicationReceiptCommittedError,
                "committed leaf=receipt.json",
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

    def test_transaction_writer_reports_committed_directory_mode_drift(
        self,
    ) -> None:
        real_write = receipt_io._write_private_bytes_noreplace_at

        def write_then_change_mode(
            directory_fd: int,
            *args: object,
            **kwargs: object,
        ) -> str:
            digest = real_write(directory_fd, *args, **kwargs)
            os.fchmod(directory_fd, 0o777)
            return digest

        with (
            mock.patch.object(
                receipt_io,
                "_write_private_bytes_noreplace_at",
                side_effect=write_then_change_mode,
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.create_private_transaction_json(
                safe_root=self.safe_root,
                transaction_prefix="transaction.mode-drift.",
                expected_leaf="receipt.json",
                value={"fixture": True},
                label="fixture receipt",
            )
        self.assertEqual("receipt.json", caught.exception.leaf)
        receipts = list(self.safe_root.glob("*/receipt.json"))
        self.assertEqual(1, len(receipts))
        self.assertTrue(receipts[0].is_file())

    def test_fixed_writer_reports_committed_safe_root_mode_drift(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        real_write = receipt_io._write_private_bytes_noreplace_at

        def write_then_change_mode(
            directory_fd: int,
            *args: object,
            **kwargs: object,
        ) -> str:
            digest = real_write(directory_fd, *args, **kwargs)
            os.fchmod(directory_fd, 0o777)
            return digest

        with (
            mock.patch.object(
                receipt_io,
                "_write_private_bytes_noreplace_at",
                side_effect=write_then_change_mode,
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.write_fixed_private_json(
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                value={"fixture": True},
                label="fixture fixed receipt",
            )
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertTrue((self.safe_root / "receipt.json").is_file())

    def test_transaction_outer_close_interrupt_is_structured_and_closes_all(
        self,
    ) -> None:
        baseline_descriptors = self._open_descriptor_count()
        real_write = receipt_io._write_private_bytes_noreplace_at
        real_close = receipt_io.os.close
        armed = False
        injected = False
        postcommit_close_calls = 0

        def write_then_arm(*args: object, **kwargs: object) -> str:
            nonlocal armed
            digest = real_write(*args, **kwargs)
            armed = True
            return digest

        def close_after_commit(descriptor: int) -> None:
            nonlocal injected, postcommit_close_calls
            if armed:
                postcommit_close_calls += 1
                if not injected:
                    injected = True
                    real_close(descriptor)
                    raise KeyboardInterrupt(
                        "injected postcommit transaction close interruption"
                    )
            real_close(descriptor)

        with (
            mock.patch.object(
                receipt_io,
                "_write_private_bytes_noreplace_at",
                side_effect=write_then_arm,
            ),
            mock.patch.object(
                receipt_io.os,
                "close",
                side_effect=close_after_commit,
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.create_private_transaction_json(
                safe_root=self.safe_root,
                transaction_prefix="transaction.close-interrupt.",
                expected_leaf="receipt.json",
                value={"fixture": True},
                label="fixture receipt",
            )

        self.assertTrue(injected)
        self.assertEqual(2, postcommit_close_calls)
        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(1, len(list(self.safe_root.glob("*/receipt.json"))))
        self.assertEqual(baseline_descriptors, self._open_descriptor_count())

    def test_fixed_writer_outer_close_interrupt_is_structured(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        baseline_descriptors = self._open_descriptor_count()
        real_write = receipt_io._write_private_bytes_noreplace_at
        real_close = receipt_io.os.close
        armed = False
        injected = False

        def write_then_arm(*args: object, **kwargs: object) -> str:
            nonlocal armed
            digest = real_write(*args, **kwargs)
            armed = True
            return digest

        def close_after_commit(descriptor: int) -> None:
            nonlocal injected
            if armed and not injected:
                injected = True
                real_close(descriptor)
                raise KeyboardInterrupt(
                    "injected postcommit fixed-root close interruption"
                )
            real_close(descriptor)

        with (
            mock.patch.object(
                receipt_io,
                "_write_private_bytes_noreplace_at",
                side_effect=write_then_arm,
            ),
            mock.patch.object(
                receipt_io.os,
                "close",
                side_effect=close_after_commit,
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.write_fixed_private_json(
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                value={"fixture": True},
                label="fixture receipt",
            )

        self.assertTrue(injected)
        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertTrue((self.safe_root / "receipt.json").is_file())
        self.assertEqual(baseline_descriptors, self._open_descriptor_count())

    def test_json_wrapper_after_bytes_return_interrupt_is_committed(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        value = {"fixture": "json-wrapper-return"}
        payload = receipt_io.canonical_json_bytes(value)
        descriptor = receipt_io.open_private_directory(
            self.safe_root,
            label="fixture JSON root",
        )
        try:
            with (
                self._interrupt_once_after_return(
                    receipt_io._write_private_bytes_noreplace_at.__code__,
                    receipt_io.write_private_json_noreplace_at.__code__,
                    label="bytes-to-JSON wrapper",
                ),
                self.assertRaises(
                    receipt_io.PublicationReceiptCommittedError
                ) as caught,
            ):
                receipt_io.write_private_json_noreplace_at(
                    descriptor,
                    "receipt.json",
                    value,
                    label="fixture receipt",
                )
        finally:
            os.close(descriptor)

        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            caught.exception.digest,
        )
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(payload, (self.safe_root / "receipt.json").read_bytes())

    def test_transaction_after_writer_return_interrupt_has_attempt_path(
        self,
    ) -> None:
        value = {"fixture": "transaction-return"}
        payload = receipt_io.canonical_json_bytes(value)
        with (
            self._interrupt_once_after_return(
                receipt_io._write_private_bytes_noreplace_at.__code__,
                receipt_io.create_private_transaction_json.__code__,
                label="writer-to-transaction helper",
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.create_private_transaction_json(
                safe_root=self.safe_root,
                transaction_prefix="transaction.return-interrupt.",
                expected_leaf="receipt.json",
                value=value,
                label="fixture receipt",
            )

        receipts = list(
            self.safe_root.glob("transaction.return-interrupt.*/receipt.json")
        )
        self.assertEqual(1, len(receipts))
        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), caught.exception.digest)
        self.assertEqual(receipts[0], caught.exception.path)
        self.assertNotIn(str(self.parent), str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(payload, receipts[0].read_bytes())

    def test_transaction_uncertain_return_has_indeterminate_attempt_path(
        self,
    ) -> None:
        real_write = receipt_io._write_private_bytes_noreplace_at

        def write_then_make_visibility_uncertain(
            *args: object,
            **kwargs: object,
        ) -> str:
            state = cast(
                receipt_io._PrivateFilePublicationState,
                kwargs["publication_state"],
            )
            real_write(*args, **kwargs)
            state.visibility = receipt_io._VISIBILITY_INDETERMINATE
            raise KeyboardInterrupt("injected uncertain outer return")

        with (
            mock.patch.object(
                receipt_io,
                "_write_private_bytes_noreplace_at",
                side_effect=write_then_make_visibility_uncertain,
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.create_private_transaction_json(
                safe_root=self.safe_root,
                transaction_prefix="transaction.uncertain-return.",
                expected_leaf="receipt.json",
                value={"fixture": "uncertain-return"},
                label="fixture receipt",
            )

        receipts = list(
            self.safe_root.glob("transaction.uncertain-return.*/receipt.json")
        )
        self.assertEqual(1, len(receipts))
        self.assertEqual("indeterminate", caught.exception.visibility)
        self.assertEqual(receipts[0], caught.exception.path)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)

    def test_fixed_writer_after_writer_return_interrupt_is_committed(self) -> None:
        self.safe_root.mkdir(mode=0o700)
        os.chmod(self.safe_root, 0o700)
        value = {"fixture": "fixed-return"}
        payload = receipt_io.canonical_json_bytes(value)
        with (
            self._interrupt_once_after_return(
                receipt_io._write_private_bytes_noreplace_at.__code__,
                receipt_io.write_fixed_private_json.__code__,
                label="writer-to-fixed helper",
            ),
            self.assertRaises(
                receipt_io.PublicationReceiptCommittedError
            ) as caught,
        ):
            receipt_io.write_fixed_private_json(
                safe_root=self.safe_root,
                expected_leaf="receipt.json",
                value=value,
                label="fixture receipt",
            )

        self.assertEqual("committed", caught.exception.visibility)
        self.assertEqual("receipt.json", caught.exception.leaf)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), caught.exception.digest)
        self.assertIsInstance(caught.exception.__cause__, KeyboardInterrupt)
        self.assertEqual(payload, (self.safe_root / "receipt.json").read_bytes())

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
        sibling_root = self.parent / "publication-receipts-evil"
        sibling_root.mkdir(mode=0o700)
        sibling_transaction = sibling_root / "transaction.input"
        sibling_transaction.mkdir(mode=0o700)
        sibling_path = sibling_transaction / "receipt.json"
        sibling_path.write_bytes(b'{"kind":"evil"}\n')
        os.chmod(sibling_path, 0o600)
        for candidate, leaf, depth in (
            (path.parent / "../transaction.input/receipt.json", "receipt.json", 1),
            (path, "other.json", 1),
            (path, "receipt.json", 0),
            (sibling_path, "receipt.json", 1),
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
