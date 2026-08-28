#!/usr/bin/env python3
"""Transaction, boundary, and recovery tests for crates.io publication."""

from __future__ import annotations

import contextlib
import copy
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from collections.abc import Sequence
from unittest import mock

from bounded_process import BoundedResult
import crates_io_publication as publication
import crates_io_publication_contract as contract
import publication_receipt_io as receipt_io
import test_release_publication_contract as release_contract_tests
import test_rust_publish_contract as rust_contract_tests


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode(
        "ascii"
    ) + b"\n"


class FixedClock:
    def __init__(self, value: str = "2026-08-15T02:00:00Z") -> None:
        self.value = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.UTC
        )

    def __call__(self) -> dt.datetime:
        return self.value


class RegistryFixture:
    def __init__(
        self,
        packages: Sequence[publication.LocalCrate],
        *,
        published_count: int = 0,
    ) -> None:
        self.packages = {package.name: package for package in packages}
        self.published = {
            package.name for package in tuple(packages)[:published_count]
        }
        self.fetch_calls: list[str] = []
        self.upload_calls: list[str] = []
        self.api_overrides: dict[str, dict[str, object]] = {}
        self.sparse_overrides: dict[str, dict[str, object]] = {}
        self._sparse_names = {
            publication._sparse_path(package.name): package.name
            for package in packages
        }

    def api(
        self,
        url: str,
        *,
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> publication.HttpResponse:
        del timeout_seconds, maximum_bytes
        self.fetch_calls.append(url)
        crate_name, version = url.rsplit("/", 2)[-2:]
        package = self.packages[crate_name]
        if crate_name not in self.published:
            return publication.HttpResponse(404, url, b"{}\n")
        record: dict[str, object] = {
            "checksum": package.sha256,
            "crate": crate_name,
            "num": version,
            "yanked": False,
        }
        record.update(self.api_overrides.get(crate_name, {}))
        return publication.HttpResponse(200, url, _json({"version": record}))

    def sparse(
        self,
        url: str,
        *,
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> publication.HttpResponse:
        del timeout_seconds, maximum_bytes
        self.fetch_calls.append(url)
        sparse_path = url.removeprefix(f"{contract.CRATES_IO_SPARSE_INDEX}/")
        crate_name = self._sparse_names[sparse_path]
        package = self.packages[crate_name]
        if crate_name not in self.published:
            return publication.HttpResponse(404, url, b"")
        record: dict[str, object] = {
            "cksum": package.sha256,
            "name": crate_name,
            "vers": package.version,
            "yanked": False,
        }
        record.update(self.sparse_overrides.get(crate_name, {}))
        return publication.HttpResponse(200, url, _json(record))

    def upload(
        self,
        package: publication.LocalCrate,
        *,
        credential: str,
    ) -> BoundedResult:
        if credential != "cio_fixture_token_123456789":
            raise AssertionError("unexpected credential")
        self.upload_calls.append(package.name)
        self.published.add(package.name)
        return BoundedResult(returncode=0)


class CratesIoPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(publication.pwd)
        account_record = publication.pwd.getpwuid(os.geteuid())
        trusted_test_parent = pathlib.Path(account_record.pw_dir).resolve(
            strict=True
        )
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".qperiapt-crates-test.",
            dir=trusted_test_parent,
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.account_home = self.root / "account-home"
        self.account_home.mkdir(mode=0o700)
        qperiapt_root = self.account_home / ".q-periapt"
        qperiapt_root.mkdir(mode=0o700)
        publication_state = qperiapt_root / "publication-state"
        publication_state.mkdir(mode=0o700)
        self.production_state_root = (
            publication_state / "crates.io-v0.1.4"
        )
        self.production_state_root.mkdir(mode=0o700)
        passwd_patch = mock.patch.object(
            publication.pwd,
            "getpwuid",
            return_value=mock.Mock(pw_dir=os.fspath(self.account_home)),
        )
        passwd_patch.start()
        self.addCleanup(passwd_patch.stop)
        self.receipt_root = self.root / "receipts"
        self.receipt_root.mkdir(mode=0o700)
        self.journal_root = self.root / "journal"
        self.handoff_root = self.root / "handoffs"
        self.handoff_root.mkdir(mode=0o700)
        rust_module = rust_contract_tests.rust_publish_contract
        (
            self.package_root,
            self.package_device,
            self.package_inode,
        ) = rust_module.create_owned_package_directory(
            "qperiapt-package-verification."
        )
        (
            self.staging_root,
            self.staging_device,
            self.staging_inode,
        ) = rust_module.create_owned_package_directory(
            "qperiapt-rust-package-handoff-stage."
        )
        self.addCleanup(
            self._remove_owned_if_present,
            self.package_root,
            self.package_device,
            self.package_inode,
        )
        self.addCleanup(
            self._remove_owned_if_present,
            self.staging_root,
            self.staging_device,
            self.staging_inode,
        )
        self.transcript_path = (
            self.staging_root / publication.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
        )
        self.stderr_path = (
            self.staging_root / publication.RUST_PACKAGE_HANDOFF_STDERR_NAME
        )
        self.package_archive_root = self.package_root / "package"
        self.package_archive_root.mkdir(mode=0o700)
        self.package_paths: list[pathlib.Path] = []
        for index, (name, _dependencies) in enumerate(
            contract.CRATE_PUBLICATION_TOPOLOGY, start=1
        ):
            path = (
                self.package_archive_root
                / f"{name}-{contract.PRODUCT_VERSION}.crate"
            )
            path.write_bytes(f"exact crate fixture {index} {name}\n".encode("ascii"))
            os.chmod(path, 0o600)
            self.package_paths.append(path)
        self.source = publication.SourceIdentity(
            source_parent_commit=rust_contract_tests.SOURCE_COMMIT,
            tag_commit="1" * 40,
            tag_tree="2" * 40,
            canonical_source_tree_sha256="3" * 64,
        )
        publication.stage_verified_crate_handoff(
            self.package_root,
            self.staging_root,
            package_device=self.package_device,
            package_inode=self.package_inode,
            staging_device=self.staging_device,
            staging_inode=self.staging_inode,
        )
        transcript = (
            "\n".join(rust_contract_tests.valid_rust_package_contract_transcript())
            + "\n"
        ).encode("utf-8")
        staging_fd = receipt_io.open_private_directory(
            self.staging_root,
            label="test Rust package handoff stage",
        )
        try:
            publication.persist_rust_package_contract_capture(
                staging_fd,
                BoundedResult(
                    returncode=0,
                    stdout=transcript,
                    stderr=b"inner contract progress\n",
                ),
            )
        finally:
            os.close(staging_fd)
        self.handoff_source = publication.RustPackageHandoffSource(
            source_commit=rust_contract_tests.SOURCE_COMMIT,
            source_tree="4" * 40,
            canonical_source_tree_sha256=(
                self.source.canonical_source_tree_sha256
            ),
        )
        self.handoff_manifest_path, self.handoff_manifest_sha256 = (
            publication.finalize_rust_package_handoff(
                self.staging_root,
                staging_device=self.staging_device,
                staging_inode=self.staging_inode,
                handoff_root=self.handoff_root,
                source_inspector=lambda: self.handoff_source,
            )
        )

    @staticmethod
    def _remove_owned_if_present(
        path: pathlib.Path, device: int, inode: int
    ) -> None:
        if path.exists() and not path.is_symlink():
            rust_contract_tests.rust_publish_contract.remove_owned_package_directory(
                path, device, inode
            )

    def evidence(self) -> publication.LocalPublicationEvidence:
        return publication.load_local_publication_evidence(
            self.source,
            self.handoff_manifest_path,
            self.handoff_manifest_sha256,
            handoff_root=self.handoff_root,
            source_tree_resolver=lambda _commit: self.handoff_source.source_tree,
            source_transition_verifier=lambda _source, _path, _digest: None,
        )

    def cli_selected_handoff(self) -> publication.ResultsSelectedHandoff:
        return publication.ResultsSelectedHandoff(
            path=self.handoff_manifest_path,
            relative_path=pathlib.PurePosixPath(
                "target/qperiapt-rust-package-handoffs/"
                f"transaction.1-{'a' * 32}/"
                f"{publication.RUST_PACKAGE_HANDOFF_MANIFEST_NAME}"
            ),
            sha256=self.handoff_manifest_sha256,
        )

    def stable_results_handoff_manifest(
        self,
        selected_path: str,
        selected_sha256: str,
    ) -> dict[str, object]:
        manifest: dict[str, object] = {
            "proof_source_tree_sha256": self.source.canonical_source_tree_sha256,
            "provenance": {
                "snapshot_commit": self.source.source_parent_commit,
            },
        }
        release_contract_tests.rebind_stable_current_source(
            manifest,
            source_commit=self.source.source_parent_commit,
            source_digest=self.source.canonical_source_tree_sha256,
        )
        stable_fixture = release_contract_tests.source_manifest_fixture()
        rust_publish = release_contract_tests.rebind_rust_publish_source(
            stable_fixture["rust_publish"],
            source_commit=self.source.source_parent_commit,
            source_digest=self.source.canonical_source_tree_sha256,
        )
        rust_publish["handoff_manifest_path"] = selected_path
        rust_publish["handoff_manifest_sha256"] = selected_sha256
        manifest["rust_publish"] = rust_publish
        return manifest

    def run_publication(
        self, **kwargs: object
    ) -> publication.PublicationRun:
        return publication.run_publication_transaction(
            self.source,
            self.handoff_manifest_path,
            self.handoff_manifest_sha256,
            handoff_root=self.handoff_root,
            source_tree_resolver=lambda _commit: self.handoff_source.source_tree,
            source_transition_verifier=lambda _source, _path, _digest: None,
            **kwargs,
        )

    def assert_precommit_journal_residue_recovers_before_upload(
        self,
        residue_name: str,
    ) -> None:
        evidence = self.evidence()
        with self.assertRaises(publication.CratesIoPublicationError):
            publication.load_unresolved_upload_intents(
                evidence,
                journal_root=self.journal_root,
            )
        registry = RegistryFixture(evidence.crates)
        upload_calls: list[str] = []

        def fail_first_upload(
            package: publication.LocalCrate,
            *,
            credential: str,
        ) -> BoundedResult:
            self.assertEqual("cio_fixture_token_123456789", credential)
            self.assertFalse(
                (self.journal_root / residue_name).exists(),
                "precommit residue survived until uploader invocation",
            )
            upload_calls.append(package.name)
            raise RuntimeError("injected upload interruption")

        _values, writer = self.memory_writer()
        with self.assertRaises(publication.CratesIoUploadOutcomeUnknownError):
            self.run_publication(
                mode="publish",
                api_fetcher=registry.api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
                sleeper=lambda _seconds: None,
                receipt_writer=writer,
                journal_root=self.journal_root,
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=(
                    lambda: "cio_fixture_token_123456789"
                ),
                lock_factory=contextlib.nullcontext,
                upload_runner=fail_first_upload,
                poll_attempts=1,
                poll_interval_seconds=0,
            )
        self.assertEqual([contract.PUBLISHABLE_CRATES[0]], upload_calls)
        self.assertFalse((self.journal_root / residue_name).exists())

    def run_handoff_signal_window(
        self,
        phase: str,
    ) -> tuple[subprocess.CompletedProcess[bytes], pathlib.Path]:
        signal_root = self.root / f"signal-{phase}-handoffs"
        signal_root.mkdir(mode=0o700)
        ready = self.root / f"signal-{phase}.ready"
        observed = self.root / f"signal-{phase}.observed"
        proceed = self.root / f"signal-{phase}.proceed"
        source = """
import os
import pathlib
import signal
import sys

from crates_io_publication import (
    RustPackageHandoffSource,
    finalize_rust_package_handoff_for_cli,
)

stage = pathlib.Path(sys.argv[1])
handoff_root = pathlib.Path(sys.argv[4])
phase = sys.argv[8]
ready = pathlib.Path(sys.argv[9])
observed = pathlib.Path(sys.argv[10])
proceed = pathlib.Path(sys.argv[11])
source = RustPackageHandoffSource(
    source_commit=sys.argv[5],
    source_tree=sys.argv[6],
    canonical_source_tree_sha256=sys.argv[7],
)

def window() -> None:
    ready.write_bytes(b"ready")
    os.chmod(ready, 0o600)
    signal.pause()
    observed.write_bytes(b"observed")
    os.chmod(observed, 0o600)
    while not proceed.exists():
        signal.pause()

hooks = {
    "precommit_hook": window if phase == "precommit" else None,
    "commit_boundary_hook": window if phase == "visibility" else None,
    "postcommit_hook": window if phase == "postcommit" else None,
}
finalize_rust_package_handoff_for_cli(
    stage,
    staging_device=int(sys.argv[2]),
    staging_inode=int(sys.argv[3]),
    handoff_root=handoff_root,
    source_inspector=lambda: source,
    marker_path_formatter=(
        lambda path: "target/test-rust-handoffs/" + path.parent.name + "/" + path.name
    ),
    **hooks,
)
"""
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                source,
                os.fspath(self.staging_root),
                str(self.staging_device),
                str(self.staging_inode),
                os.fspath(signal_root),
                self.handoff_source.source_commit,
                self.handoff_source.source_tree,
                self.handoff_source.canonical_source_tree_sha256,
                phase,
                os.fspath(ready),
                os.fspath(observed),
                os.fspath(proceed),
            ],
            cwd=pathlib.Path(__file__).resolve().parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

        def wait_for(path: pathlib.Path, label: str) -> None:
            deadline = time.monotonic() + 10
            while not path.exists():
                if process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=1)
                    self.fail(
                        f"signal child exited before {label}: "
                        f"status={process.returncode} stdout={stdout!r} stderr={stderr!r}"
                    )
                if time.monotonic() >= deadline:
                    process.kill()
                    process.communicate(timeout=5)
                    self.fail(f"signal child did not reach {label}")
                time.sleep(0.01)

        if phase != "success":
            wait_for(ready, f"{phase} window")
            os.kill(process.pid, signal.SIGTERM)
            if phase != "precommit":
                wait_for(observed, f"{phase} signal observation")
                proceed.write_bytes(b"proceed")
                os.chmod(proceed, 0o600)
                os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        return (
            subprocess.CompletedProcess(
                process.args,
                process.returncode,
                stdout,
                stderr,
            ),
            signal_root,
        )

    def memory_writer(
        self,
    ) -> tuple[
        list[dict[str, object]], publication.ReceiptWriter
    ]:
        values: list[dict[str, object]] = []

        def writer(value: dict[str, object]) -> tuple[pathlib.Path, str]:
            values.append(copy.deepcopy(value))
            payload = _json(value)
            return (
                self.receipt_root / f"memory-{len(values)}.json",
                hashlib.sha256(payload).hexdigest(),
            )

        return values, writer

    def test_dry_run_reuses_complete_transcript_validator_without_network(self) -> None:
        def unexpected_fetch(*_args: object, **_kwargs: object) -> publication.HttpResponse:
            raise AssertionError("dry-run must not access crates.io")

        result = self.run_publication(
            mode="dry-run",
            api_fetcher=unexpected_fetch,
            sparse_fetcher=unexpected_fetch,
        )
        self.assertIsNone(result.receipt)
        self.assertEqual(contract.PUBLISHABLE_CRATES, result.planned_crates)
        self.assertEqual((), result.upload_attempts)

    def test_handoff_stager_rejects_legacy_root_archive_layout(self) -> None:
        rust_module = rust_contract_tests.rust_publish_contract
        legacy_root, legacy_device, legacy_inode = (
            rust_module.create_owned_package_directory(
                "qperiapt-package-verification."
            )
        )
        stage, stage_device, stage_inode = (
            rust_module.create_owned_package_directory(
                "qperiapt-rust-package-handoff-stage."
            )
        )
        self.addCleanup(
            self._remove_owned_if_present,
            legacy_root,
            legacy_device,
            legacy_inode,
        )
        self.addCleanup(
            self._remove_owned_if_present,
            stage,
            stage_device,
            stage_inode,
        )
        for index, (name, _dependencies) in enumerate(
            contract.CRATE_PUBLICATION_TOPOLOGY,
            start=1,
        ):
            archive = legacy_root / f"{name}-{contract.PRODUCT_VERSION}.crate"
            archive.write_bytes(f"legacy fixture {index}\n".encode("ascii"))
            os.chmod(archive, 0o600)

        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "cannot open Rust Cargo package archive directory",
        ):
            publication.stage_verified_crate_handoff(
                legacy_root,
                stage,
                package_device=legacy_device,
                package_inode=legacy_inode,
                staging_device=stage_device,
                staging_inode=stage_inode,
            )
        self.assertEqual((), tuple(stage.iterdir()))

    def test_handoff_stager_rejects_inexact_cargo_archive_inventory(
        self,
    ) -> None:
        rust_module = rust_contract_tests.rust_publish_contract

        def new_stage() -> tuple[pathlib.Path, int, int]:
            stage, device, inode = rust_module.create_owned_package_directory(
                "qperiapt-rust-package-handoff-stage."
            )
            self.addCleanup(
                self._remove_owned_if_present,
                stage,
                device,
                inode,
            )
            return stage, device, inode

        first = self.package_paths[0]
        first_payload = first.read_bytes()
        first.unlink()
        missing_stage, missing_device, missing_inode = new_stage()
        try:
            with self.assertRaisesRegex(
                publication.CratesIoPublicationError,
                "archive inventory differs",
            ):
                publication.stage_verified_crate_handoff(
                    self.package_root,
                    missing_stage,
                    package_device=self.package_device,
                    package_inode=self.package_inode,
                    staging_device=missing_device,
                    staging_inode=missing_inode,
                )
            self.assertEqual((), tuple(missing_stage.iterdir()))
        finally:
            first.write_bytes(first_payload)
            os.chmod(first, 0o600)

        extra = self.package_archive_root / "unexpected.crate"
        extra.write_bytes(b"unexpected\n")
        os.chmod(extra, 0o600)
        extra_stage, extra_device, extra_inode = new_stage()
        try:
            with self.assertRaisesRegex(
                publication.CratesIoPublicationError,
                "archive inventory differs",
            ):
                publication.stage_verified_crate_handoff(
                    self.package_root,
                    extra_stage,
                    package_device=self.package_device,
                    package_inode=self.package_inode,
                    staging_device=extra_device,
                    staging_inode=extra_inode,
                )
            self.assertEqual((), tuple(extra_stage.iterdir()))
        finally:
            extra.unlink()

    def test_verify_binds_api_sparse_and_exact_local_archive_hashes(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates, published_count=10)
        result = self.run_publication(
            mode="verify",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=FixedClock(),
            write_verify_receipt=False,
        )
        self.assertIsNotNone(result.receipt)
        contract.validate_crates_io_publication_receipt(result.receipt)
        self.assertEqual(
            contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED,
            result.receipt["status"],
        )
        self.assertEqual(
            self.handoff_manifest_sha256,
            result.receipt["observation"]["package_contract"][
                "handoff_sha256"
            ],
        )
        for package, crate in zip(evidence.crates, result.receipt["crates"]):
            self.assertEqual(package.sha256, crate["crate_sha256"])
            self.assertEqual(package.sha256, crate["crates_io_api"]["checksum"])
            self.assertEqual(package.sha256, crate["sparse_index"]["checksum"])

    def test_handoff_missing_extra_and_replaced_archive_fail(self) -> None:
        transaction = self.handoff_manifest_path.parent
        first = transaction / self.package_paths[0].name
        payload = first.read_bytes()
        first.unlink()
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "entry set differs"
        ):
            self.evidence()

        first.write_bytes(payload)
        os.chmod(first, 0o600)
        extra = transaction / "unexpected.crate"
        extra.write_bytes(b"extra")
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "entry set differs"
        ):
            self.evidence()

        extra.unlink()
        first.write_bytes(b"replacement")
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "differs from its manifest"
        ):
            self.evidence()

    def test_handoff_manifest_transcript_and_source_drift_fail(self) -> None:
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "explicit marker"
        ):
            publication.load_local_publication_evidence(
                self.source,
                self.handoff_manifest_path,
                "f" * 64,
                handoff_root=self.handoff_root,
                source_tree_resolver=lambda _commit: self.handoff_source.source_tree,
                source_transition_verifier=lambda _source, _path, _digest: None,
            )

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "source identity differs"
        ):
            publication.load_local_publication_evidence(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
                handoff_root=self.handoff_root,
                source_tree_resolver=lambda _commit: "5" * 40,
                source_transition_verifier=lambda _source, _path, _digest: None,
            )

        transcript = (
            self.handoff_manifest_path.parent
            / publication.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
        )
        original_transcript = transcript.read_bytes()
        transcript.write_bytes(original_transcript + b"drift\n")
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "differs from its manifest"
        ):
            self.evidence()

    def test_handoff_upload_attempted_field_is_exact_false(self) -> None:
        original = self.handoff_manifest_path.read_bytes()
        value = json.loads(original)
        for mutation in (True, None):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(value)
                if mutation is None:
                    del changed["upload_attempted"]
                else:
                    changed["upload_attempted"] = mutation
                payload = _json(changed)
                self.handoff_manifest_path.write_bytes(payload)
                os.chmod(self.handoff_manifest_path, 0o600)
                with self.assertRaisesRegex(
                    publication.CratesIoPublicationError,
                    "manifest keys differ|upload_attempted=false",
                ):
                    publication.load_local_publication_evidence(
                        self.source,
                        self.handoff_manifest_path,
                        hashlib.sha256(payload).hexdigest(),
                        handoff_root=self.handoff_root,
                        source_tree_resolver=(
                            lambda _commit: self.handoff_source.source_tree
                        ),
                        source_transition_verifier=lambda _source, _path, _digest: None,
                    )
                self.handoff_manifest_path.write_bytes(original)
                os.chmod(self.handoff_manifest_path, 0o600)

    def test_handoff_binds_source_parent_s_not_results_tag_tree(self) -> None:
        evidence = self.evidence()
        shared = publication.load_rust_package_handoff_snapshot(
            self.handoff_manifest_path,
            self.handoff_manifest_sha256,
            self.handoff_source,
            handoff_root=self.handoff_root,
        )
        self.assertEqual(self.handoff_manifest_sha256, shared.manifest.sha256)
        self.assertEqual(
            rust_contract_tests.SOURCE_COMMIT,
            shared.package_contract.source_commit,
        )
        self.assertEqual(10, len(shared.crates))
        self.assertEqual(shared.transcript.sha256, evidence.transcript_sha256)
        self.assertEqual(
            self.source.source_parent_commit,
            evidence.package_contract.source_commit,
        )
        self.assertEqual(self.handoff_source.source_tree, evidence.handoff_source_tree)
        self.assertNotEqual(self.source.tag_tree, evidence.handoff_source_tree)
        self.assertEqual(
            0o700, stat.S_IMODE(self.handoff_manifest_path.parent.stat().st_mode)
        )
        self.assertEqual(
            0o600, stat.S_IMODE(self.handoff_manifest_path.stat().st_mode)
        )
        self.assertEqual(1, self.handoff_manifest_path.stat().st_nlink)
        self.assertEqual(
            publication._handoff_inventory(),
            frozenset(path.name for path in self.handoff_manifest_path.parent.iterdir()),
        )
        self.assertNotIn(
            publication.RUST_PACKAGE_HANDOFF_STDERR_NAME,
            publication._handoff_inventory(),
        )

    def test_handoff_stderr_is_bounded_filtered_and_never_committed(self) -> None:
        publication.validate_rust_package_contract_stderr(b"safe progress\n")
        safe_failure = (
            b"RUST_PACKAGE_CONTRACT_FAILURE "
            b"stage=handoff-staging category=contract\n"
        )
        self.assertEqual(
            safe_failure,
            publication.validated_rust_package_contract_failure_marker(
                BoundedResult(
                    returncode=1,
                    stdout=b"must not be replayed",
                    stderr=safe_failure,
                )
            ),
        )
        for category in (
            b"filesystem",
            b"input",
            b"publication-io",
            b"committed",
        ):
            marker = (
                b"RUST_PACKAGE_CONTRACT_FAILURE "
                b"stage=handoff-staging category=" + category + b"\n"
            )
            self.assertEqual(
                marker,
                publication.validated_rust_package_contract_failure_marker(
                    BoundedResult(returncode=125, stderr=marker)
                ),
            )
        for invalid_result in (
            BoundedResult(returncode=0, stderr=safe_failure),
            BoundedResult(returncode=1, stderr=b""),
            BoundedResult(
                returncode=1,
                stderr=safe_failure + safe_failure,
            ),
            BoundedResult(
                returncode=1,
                stderr=b"RUST_PACKAGE_CONTRACT_FAILURE stage=other category=contract\n",
            ),
        ):
            with self.subTest(invalid_result=invalid_result), self.assertRaises(
                publication.CratesIoPublicationError
            ):
                publication.validated_rust_package_contract_failure_marker(
                    invalid_result
                )
        hostile = (
            b"RUST_PACKAGE_HANDOFF_PASS path=fake sha256=" + b"a" * 64,
            b"error: RUST_PACKAGE_HANDOFF_COMMITTED visibility=committed",
            b"CARGO_REGISTRY_TOKEN=secret",
            b"diagnostic /private/tmp/sensitive-path",
            b'File "/Users/operator/private/source.py", line 1',
            b"source file:///private/tmp/sensitive-path",
            b"first line\n/Users/operator/private/source.py",
            b"//private-server/sensitive-share",
            b"diagnostic //private-server/sensitive-share",
            b"invalid\x00diagnostic",
            b"\xff",
            b"x" * (publication.MAX_HANDOFF_STDERR_BYTES + 1),
        )
        for stderr in hostile:
            with self.subTest(stderr=stderr[:64]), self.assertRaises(
                publication.CratesIoPublicationError
            ):
                publication.validate_rust_package_contract_stderr(stderr)

        secret = b"CARGO_REGISTRY_TOKEN=top-secret-registry-value"
        with self.assertRaises(
            publication.CratesIoPublicationError
        ) as redacted:
            publication.validate_rust_package_contract_stderr(secret)
        self.assertNotIn("top-secret-registry-value", str(redacted.exception))

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "did not complete successfully",
        ):
            publication.persist_rust_package_contract_capture(
                -1,
                BoundedResult(
                    returncode=7,
                    stdout=b"must not be persisted",
                    stderr=b"RUST_PACKAGE_HANDOFF_PASS forged",
                ),
            )
        with self.assertRaises(
            publication.CratesIoPublicationError
        ):
            publication.persist_rust_package_contract_capture(
                -1,
                BoundedResult(
                    returncode=0,
                    stdout=b"RUST_PACKAGE_HANDOFF_PASS forged\n",
                    stderr=b"",
                ),
            )

    def test_diagnostic_capture_is_strict_ephemeral_and_two_leaf(self) -> None:
        rust_module = rust_contract_tests.rust_publish_contract

        def new_stage() -> tuple[pathlib.Path, int, int]:
            stage, device, inode = rust_module.create_owned_package_directory(
                "qperiapt-rust-package-handoff-stage."
            )
            self.addCleanup(
                self._remove_owned_if_present,
                stage,
                device,
                inode,
            )
            return stage, device, inode

        diagnostic = (
            "\n".join(
                rust_contract_tests.valid_rust_package_diagnostic_transcript()
            )
            + "\n"
        ).encode("utf-8")
        clean = (
            "\n".join(
                rust_contract_tests.valid_rust_package_contract_transcript()
            )
            + "\n"
        ).encode("utf-8")
        stage, stage_device, stage_inode = new_stage()
        descriptor = receipt_io.open_private_directory(
            stage,
            label="test Rust package diagnostic stage",
        )
        try:
            transcript_digest, stderr_digest = (
                publication.persist_rust_package_diagnostic_capture(
                    descriptor,
                    BoundedResult(
                        returncode=0,
                        stdout=diagnostic,
                        stderr=b"diagnostic progress\n",
                    ),
                )
            )
        finally:
            os.close(descriptor)
        self.assertEqual(
            hashlib.sha256(diagnostic).hexdigest(),
            transcript_digest,
        )
        self.assertEqual(
            hashlib.sha256(b"diagnostic progress\n").hexdigest(),
            stderr_digest,
        )
        self.assertEqual(
            {
                publication.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                publication.RUST_PACKAGE_HANDOFF_STDERR_NAME,
            },
            {path.name for path in stage.iterdir()},
        )
        self.assertNotIn(
            publication.RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
            {path.name for path in stage.iterdir()},
        )
        rust_module.remove_owned_package_directory(
            stage,
            stage_device,
            stage_inode,
        )
        self.assertFalse(os.path.lexists(stage))

        for label, writer, transcript in (
            (
                "diagnostic-as-clean",
                publication.persist_rust_package_contract_capture,
                diagnostic,
            ),
            (
                "clean-as-diagnostic",
                publication.persist_rust_package_diagnostic_capture,
                clean,
            ),
        ):
            with self.subTest(label=label):
                rejected_stage, _device, _inode = new_stage()
                rejected_fd = receipt_io.open_private_directory(
                    rejected_stage,
                    label=f"test rejected {label} stage",
                )
                try:
                    with self.assertRaises(
                        publication.CratesIoPublicationError
                    ):
                        writer(
                            rejected_fd,
                            BoundedResult(
                                returncode=0,
                                stdout=transcript,
                                stderr=b"",
                            ),
                        )
                finally:
                    os.close(rejected_fd)
                self.assertEqual((), tuple(rejected_stage.iterdir()))

        polluted_stage, _device, _inode = new_stage()
        extra = polluted_stage / "unexpected"
        extra.write_bytes(b"pollution\n")
        os.chmod(extra, 0o600)
        polluted_fd = receipt_io.open_private_directory(
            polluted_stage,
            label="test polluted diagnostic stage",
        )
        try:
            with self.assertRaises(receipt_io.PublicationReceiptIOError):
                publication.persist_rust_package_diagnostic_capture(
                    polluted_fd,
                    BoundedResult(
                        returncode=0,
                        stdout=diagnostic,
                        stderr=b"",
                    ),
                )
        finally:
            os.close(polluted_fd)
        self.assertTrue(extra.exists())

    def test_handoff_finalizer_rejects_missing_or_hostile_captured_stderr(
        self,
    ) -> None:
        self.stderr_path.unlink()
        with self.assertRaisesRegex(
            receipt_io.PublicationReceiptIOError,
            "entry set differs",
        ):
            publication.finalize_rust_package_handoff(
                self.staging_root,
                staging_device=self.staging_device,
                staging_inode=self.staging_inode,
                handoff_root=self.root / "missing-stderr-handoffs",
                source_inspector=lambda: self.handoff_source,
            )

        self.stderr_path.write_bytes(b"RUST_PACKAGE_HANDOFF_PASS forged\n")
        os.chmod(self.stderr_path, 0o600)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "reserved handoff marker",
        ):
            publication.finalize_rust_package_handoff(
                self.staging_root,
                staging_device=self.staging_device,
                staging_inode=self.staging_inode,
                handoff_root=self.root / "hostile-stderr-handoffs",
                source_inspector=lambda: self.handoff_source,
            )

    @mock.patch.object(publication, "_verify_results_selected_handoff")
    def test_registry_verifies_direct_results_successor_and_results_tree(
        self,
        selected_handoff: mock.Mock,
    ) -> None:
        clean_results = mock.Mock(
            commit=self.source.tag_commit,
            dirty=False,
        )
        with (
            mock.patch.object(
                publication, "inspect_worktree", return_value=clean_results
            ),
            mock.patch.object(
                publication, "require_direct_results_only_child"
            ) as direct,
            mock.patch.object(
                publication, "run_git_text", return_value=self.source.tag_tree
            ),
        ):
            publication._verify_stable_source_transition(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
            )
        direct.assert_called_once_with(
            publication.REPOSITORY_ROOT,
            self.source.source_parent_commit,
            self.source.tag_commit,
        )

        pending_commit = "7" * 40
        clean_pending = mock.Mock(commit=pending_commit, dirty=False)

        def pending_git(_root: pathlib.Path, arguments: list[str]) -> str:
            if arguments[:2] == ["rev-parse", "--verify"]:
                return self.source.tag_tree
            self.assertEqual(
                ["rev-list", "--merges", f"{self.source.tag_commit}..{pending_commit}"],
                arguments,
            )
            return ""

        with (
            mock.patch.object(
                publication, "inspect_worktree", return_value=clean_pending
            ),
            mock.patch.object(publication, "require_direct_results_only_child"),
            mock.patch.object(
                publication, "require_results_only_descendant"
            ) as descendant,
            mock.patch.object(
                publication, "run_git_text", side_effect=pending_git
            ),
        ):
            publication._verify_stable_source_transition(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
            )
        descendant.assert_called_once_with(
            publication.REPOSITORY_ROOT,
            self.source.tag_commit,
            pending_commit,
        )

        with (
            mock.patch.object(
                publication, "inspect_worktree", return_value=clean_results
            ),
            mock.patch.object(
                publication,
                "require_direct_results_only_child",
                side_effect=publication.GitProvenanceError(
                    "results commit is not a direct child"
                ),
            ),
            self.assertRaisesRegex(
                publication.CratesIoPublicationError, "not a direct child"
            ),
        ):
            publication._verify_stable_source_transition(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
            )

        for message in (
            "commit is not a descendant",
            "publication descendant must change exactly artifact/results.json",
        ):
            with (
                self.subTest(message=message),
                mock.patch.object(
                    publication, "inspect_worktree", return_value=clean_pending
                ),
                mock.patch.object(
                    publication, "require_direct_results_only_child"
                ),
                mock.patch.object(
                    publication,
                    "require_results_only_descendant",
                    side_effect=publication.GitProvenanceError(message),
                ),
                mock.patch.object(
                    publication, "run_git_text", side_effect=pending_git
                ),
                self.assertRaisesRegex(
                    publication.CratesIoPublicationError,
                    "not a descendant|change exactly",
                ),
            ):
                publication._verify_stable_source_transition(
                    self.source,
                    self.handoff_manifest_path,
                    self.handoff_manifest_sha256,
                )

        def merge_git(_root: pathlib.Path, arguments: list[str]) -> str:
            if arguments[:2] == ["rev-parse", "--verify"]:
                return self.source.tag_tree
            return "6" * 40

        with (
            mock.patch.object(
                publication, "inspect_worktree", return_value=clean_pending
            ),
            mock.patch.object(publication, "require_direct_results_only_child"),
            mock.patch.object(publication, "run_git_text", side_effect=merge_git),
            self.assertRaisesRegex(
                publication.CratesIoPublicationError,
                "contains a merge",
            ),
        ):
            publication._verify_stable_source_transition(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
            )

        with (
            mock.patch.object(
                publication, "inspect_worktree", return_value=clean_results
            ),
            mock.patch.object(
                publication, "require_direct_results_only_child"
            ),
            mock.patch.object(publication, "run_git_text", return_value="8" * 40),
            self.assertRaisesRegex(
                publication.CratesIoPublicationError,
                "results tree differs",
            ),
        ):
            publication._verify_stable_source_transition(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
            )

        self.assertGreaterEqual(selected_handoff.call_count, 2)

    def test_registry_rejects_alternate_same_source_handoff_before_credential(
        self,
    ) -> None:
        selected_path = (
            "target/qperiapt-rust-package-handoffs/"
            f"transaction.1-{'a' * 32}/rust-package-handoff.json"
        )
        alternate_path = (
            "target/qperiapt-rust-package-handoffs/"
            f"transaction.2-{'b' * 32}/rust-package-handoff.json"
        )
        manifest = self.stable_results_handoff_manifest(
            selected_path,
            self.handoff_manifest_sha256,
        )
        with mock.patch.object(
            publication,
            "_load_tag_results_manifest",
            return_value=manifest,
        ):
            selected = publication._results_selected_handoff(self.source)
        self.assertEqual(
            publication.REPOSITORY_ROOT / pathlib.Path(selected_path),
            selected.path,
        )
        self.assertEqual(pathlib.PurePosixPath(selected_path), selected.relative_path)
        self.assertEqual(self.handoff_manifest_sha256, selected.sha256)
        publication._validate_results_selected_handoff(
            manifest,
            self.source,
            selected_path,
            self.handoff_manifest_sha256,
        )
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "exact handoff selected by results commit R",
        ):
            publication._validate_results_selected_handoff(
                manifest,
                self.source,
                alternate_path,
                self.handoff_manifest_sha256,
            )

        credential_provider = mock.Mock(return_value="fixture-credential")
        uploader = mock.Mock()
        lock_factory = mock.Mock()

        def transition(
            source: publication.SourceIdentity,
            _path: pathlib.Path,
            digest: str,
        ) -> None:
            publication._validate_results_selected_handoff(
                manifest,
                source,
                alternate_path,
                digest,
            )

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "exact handoff selected by results commit R",
        ):
            publication.run_publication_transaction(
                self.source,
                self.handoff_manifest_path,
                self.handoff_manifest_sha256,
                handoff_root=self.handoff_root,
                source_tree_resolver=(
                    lambda _commit: self.handoff_source.source_tree
                ),
                source_transition_verifier=transition,
                mode="publish",
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=credential_provider,
                lock_factory=lock_factory,
                upload_runner=uploader,
            )
        credential_provider.assert_not_called()
        lock_factory.assert_not_called()
        uploader.assert_not_called()

    def test_results_selected_handoff_rejects_malformed_R_authority(self) -> None:
        selected_path = (
            "target/qperiapt-rust-package-handoffs/"
            f"transaction.1-{'a' * 32}/rust-package-handoff.json"
        )
        valid = self.stable_results_handoff_manifest(
            selected_path,
            self.handoff_manifest_sha256,
        )
        missing_path = copy.deepcopy(valid)
        missing_path_rust = missing_path["rust_publish"]
        if not isinstance(missing_path_rust, dict):
            raise AssertionError("test Rust publication fixture is malformed")
        del missing_path_rust["handoff_manifest_path"]
        missing_digest = copy.deepcopy(valid)
        missing_digest_rust = missing_digest["rust_publish"]
        if not isinstance(missing_digest_rust, dict):
            raise AssertionError("test Rust publication fixture is malformed")
        del missing_digest_rust["handoff_manifest_sha256"]
        escaped = copy.deepcopy(valid)
        escaped_rust = escaped["rust_publish"]
        if not isinstance(escaped_rust, dict):
            raise AssertionError("test Rust publication fixture is malformed")
        escaped_rust["handoff_manifest_path"] = (
            "target/qperiapt-rust-package-handoffs/../outside.json"
        )
        cases = (
            ("missing-path", missing_path),
            ("missing-digest", missing_digest),
            ("escaped", escaped),
        )
        for label, manifest in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(
                    publication,
                    "_load_tag_results_manifest",
                    return_value=manifest,
                ),
                self.assertRaisesRegex(
                    publication.CratesIoPublicationError,
                    "selected Rust handoff is malformed|outside the fixed repository namespace",
                ),
            ):
                publication._results_selected_handoff(self.source)

    def test_registry_resamples_the_exact_R_selected_handoff_binding(self) -> None:
        transition_calls: list[
            tuple[publication.SourceIdentity, pathlib.Path, str]
        ] = []

        def transition(
            source: publication.SourceIdentity,
            path: pathlib.Path,
            digest: str,
        ) -> None:
            transition_calls.append((source, path, digest))

        evidence = publication.load_local_publication_evidence(
            self.source,
            self.handoff_manifest_path,
            self.handoff_manifest_sha256,
            handoff_root=self.handoff_root,
            source_tree_resolver=lambda _commit: self.handoff_source.source_tree,
            source_transition_verifier=transition,
        )
        publication._resample_local_evidence(evidence)
        self.assertEqual(
            [
                (
                    self.source,
                    self.handoff_manifest_path,
                    self.handoff_manifest_sha256,
                ),
                (
                    self.source,
                    self.handoff_manifest_path,
                    self.handoff_manifest_sha256,
                ),
            ],
            transition_calls,
        )

    def test_remote_mismatch_and_yank_fail_closed(self) -> None:
        evidence = self.evidence()
        mutations = (
            ("api", "checksum", "f" * 64, "API checksum differs"),
            ("sparse", "cksum", "e" * 64, "sparse checksum differs"),
            ("api", "yanked", True, "marks .* as yanked"),
            ("api", "num", "0.1.3", "API version differs"),
        )
        first = evidence.crates[0]
        for remote, field, value, expected in mutations:
            with self.subTest(remote=remote, field=field):
                registry = RegistryFixture(evidence.crates, published_count=1)
                overrides = (
                    registry.api_overrides
                    if remote == "api"
                    else registry.sparse_overrides
                )
                overrides[first.name] = {field: value}
                with self.assertRaisesRegex(
                    publication.CratesIoPublicationError, expected
                ):
                    publication.observe_remote_crate(
                        first,
                        api_fetcher=registry.api,
                        sparse_fetcher=registry.sparse,
                        clock=FixedClock(),
                    )

    def test_partial_prefix_resumes_without_reuploading_verified_crates(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates, published_count=3)
        verified = self.run_publication(
            mode="verify",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=FixedClock(),
            write_verify_receipt=False,
        )
        self.assertEqual(contract.PUBLICATION_STATUS_PARTIAL, verified.receipt["status"])
        values, writer = self.memory_writer()
        resumed = self.run_publication(
            previous_receipt=verified.receipt,
            mode="publish",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=FixedClock(),
            sleeper=lambda _seconds: None,
            receipt_writer=writer,
            journal_root=self.journal_root,
            execute_real_upload=True,
            irreversible_acknowledgement=(
                publication.REAL_UPLOAD_ACKNOWLEDGEMENT
            ),
            credential_provider=lambda: "cio_fixture_token_123456789",
            lock_factory=contextlib.nullcontext,
            upload_runner=registry.upload,
            poll_attempts=1,
            poll_interval_seconds=0,
        )
        expected_suffix = contract.PUBLISHABLE_CRATES[3:]
        self.assertEqual(list(expected_suffix), registry.upload_calls)
        self.assertEqual(expected_suffix, resumed.upload_attempts)
        self.assertEqual(
            contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED,
            resumed.receipt["status"],
        )
        self.assertEqual(1 + len(expected_suffix), len(values))
        for value in values:
            contract.validate_crates_io_publication_receipt(value)

    def test_timeout_or_nonzero_unknown_never_retries_and_never_verifies(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates)
        secret = "cio_secret_must_never_be_logged"
        calls: list[str] = []

        def timeout_upload(
            package: publication.LocalCrate,
            *,
            credential: str,
        ) -> BoundedResult:
            self.assertEqual(secret, credential)
            calls.append(package.name)
            raise RuntimeError(f"timeout with {secret}")

        _values, writer = self.memory_writer()
        with self.assertRaises(
            publication.CratesIoUploadOutcomeUnknownError
        ) as raised:
            self.run_publication(
                mode="publish",
                api_fetcher=registry.api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
                sleeper=lambda _seconds: None,
                receipt_writer=writer,
                journal_root=self.journal_root,
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=lambda: secret,
                lock_factory=contextlib.nullcontext,
                upload_runner=timeout_upload,
                poll_attempts=3,
                poll_interval_seconds=0,
            )
        self.assertEqual([contract.PUBLISHABLE_CRATES[0]], calls)

        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(
            contract.PUBLICATION_STATUS_PARTIAL,
            raised.exception.verified_receipt["status"],
        )
        with self.assertRaises(
            publication.CratesIoUploadOutcomeUnknownError
        ):
            self.run_publication(
                previous_receipt=raised.exception.verified_receipt,
                mode="publish",
                api_fetcher=registry.api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
                sleeper=lambda _seconds: None,
                receipt_writer=writer,
                journal_root=self.journal_root,
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=lambda: secret,
                lock_factory=contextlib.nullcontext,
                upload_runner=timeout_upload,
                poll_attempts=1,
                poll_interval_seconds=0,
            )
        self.assertEqual([contract.PUBLISHABLE_CRATES[0]], calls)

    def test_upload_journal_is_bound_to_one_exact_handoff_digest(self) -> None:
        evidence = self.evidence()
        publication.write_upload_intent(
            evidence,
            evidence.crates[0],
            journal_root=self.journal_root,
            clock=FixedClock(),
        )
        different_handoff = dataclasses.replace(
            evidence, handoff_manifest_sha256="f" * 64
        )
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "upload journal Rust package handoff differs",
        ):
            publication.load_unresolved_upload_intents(
                different_handoff, journal_root=self.journal_root
            )

    def test_upload_journal_rejects_outcome_before_future_dated_intent(
        self,
    ) -> None:
        evidence = self.evidence()
        package = evidence.crates[0]
        intent = publication.write_upload_intent(
            evidence,
            package,
            journal_root=self.journal_root,
            clock=FixedClock("2026-08-16T00:00:00Z"),
        )
        publication.write_upload_outcome(
            evidence,
            package,
            intent,
            state=publication.UPLOAD_JOURNAL_PUBLISHED,
            journal_root=self.journal_root,
            clock=FixedClock("2026-08-15T23:59:59Z"),
        )

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "upload journal outcome identity differs from its intent",
        ):
            publication.load_unresolved_upload_intents(
                evidence,
                journal_root=self.journal_root,
            )

    def test_exact_unresolved_reconcile_does_not_request_a_credential(self) -> None:
        evidence = self.evidence()
        for package in evidence.crates:
            publication.write_upload_intent(
                evidence,
                package,
                journal_root=self.journal_root,
                clock=FixedClock(),
            )
        registry = RegistryFixture(evidence.crates, published_count=10)
        provider_calls = 0

        def unavailable_provider() -> str:
            nonlocal provider_calls
            provider_calls += 1
            raise RuntimeError("credential must not be requested for reconcile")

        def unexpected_upload(
            _package: publication.LocalCrate,
            *,
            credential: str,
        ) -> BoundedResult:
            del credential
            raise AssertionError("reconcile must not call the uploader")

        values, writer = self.memory_writer()
        result = self.run_publication(
            mode="publish",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=FixedClock(),
            receipt_writer=writer,
            journal_root=self.journal_root,
            execute_real_upload=True,
            irreversible_acknowledgement=(
                publication.REAL_UPLOAD_ACKNOWLEDGEMENT
            ),
            credential_provider=unavailable_provider,
            lock_factory=contextlib.nullcontext,
            upload_runner=unexpected_upload,
        )
        self.assertEqual(0, provider_calls)
        self.assertEqual((), result.upload_attempts)
        self.assertEqual(
            contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED,
            result.receipt["status"],
        )
        self.assertEqual(1, len(values))
        self.assertEqual(
            (),
            publication.load_unresolved_upload_intents(
                evidence,
                journal_root=self.journal_root,
            ),
        )

    def test_sigkill_empty_journal_residue_recovers_before_first_upload(
        self,
    ) -> None:
        ready = self.root / "journal-empty.ready"
        source = """
import os
import pathlib
import signal
import sys

import publication_receipt_io
from crates_io_publication import _write_upload_journal_record

journal_root = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
original_mkdir = publication_receipt_io.os.mkdir
paused = False

def pause_after_transaction_mkdir(
    path: str,
    mode: int = 0o777,
    *,
    dir_fd: int | None = None,
) -> None:
    global paused
    original_mkdir(path, mode, dir_fd=dir_fd)
    if not paused and path.startswith("transaction."):
        paused = True
        ready.write_bytes(b"ready")
        os.chmod(ready, 0o600)
        signal.pause()

publication_receipt_io.os.mkdir = pause_after_transaction_mkdir
_write_upload_journal_record(
    {"fixture": "empty-precommit-residue"},
    journal_root=journal_root,
)
"""
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                source,
                os.fspath(self.journal_root),
                os.fspath(ready),
            ],
            cwd=pathlib.Path(__file__).resolve().parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        deadline = time.monotonic() + 10
        while not ready.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=1)
                self.fail(
                    "journal writer exited before empty-directory window: "
                    f"status={process.returncode} stdout={stdout!r} stderr={stderr!r}"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate(timeout=5)
                self.fail("journal writer did not reach empty-directory window")
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(-signal.SIGKILL, process.returncode)
        self.assertEqual(b"", stdout)
        self.assertEqual(b"", stderr)

        residue_transactions = tuple(self.journal_root.iterdir())
        self.assertEqual(1, len(residue_transactions))
        residue_name = residue_transactions[0].name
        self.assertEqual((), tuple(residue_transactions[0].iterdir()))
        self.assertEqual(
            0o700,
            stat.S_IMODE(residue_transactions[0].stat().st_mode),
        )
        self.assert_precommit_journal_residue_recovers_before_upload(
            residue_name
        )

    def test_sigkill_partial_journal_residue_recovers_before_first_upload(
        self,
    ) -> None:
        ready = self.root / "journal-partial.ready"
        source = """
import os
import pathlib
import signal
import sys

import publication_receipt_io
from crates_io_publication import _write_upload_journal_record

journal_root = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
original_write = publication_receipt_io.os.write
paused = False

def pause_after_partial_write(descriptor: int, payload: bytes) -> int:
    global paused
    if paused:
        return original_write(descriptor, payload)
    paused = True
    written = original_write(descriptor, payload[:1])
    ready.write_bytes(b"ready")
    os.chmod(ready, 0o600)
    signal.pause()
    return written

publication_receipt_io.os.write = pause_after_partial_write
_write_upload_journal_record(
    {"fixture": "precommit-residue"},
    journal_root=journal_root,
)
"""
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                source,
                os.fspath(self.journal_root),
                os.fspath(ready),
            ],
            cwd=pathlib.Path(__file__).resolve().parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        deadline = time.monotonic() + 10
        while not ready.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=1)
                self.fail(
                    "journal writer exited before partial-write window: "
                    f"status={process.returncode} stdout={stdout!r} stderr={stderr!r}"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate(timeout=5)
                self.fail("journal writer did not reach partial-write window")
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(-signal.SIGKILL, process.returncode)
        self.assertEqual(b"", stdout)
        self.assertEqual(b"", stderr)

        residue_transactions = tuple(self.journal_root.iterdir())
        self.assertEqual(1, len(residue_transactions))
        residue_name = residue_transactions[0].name
        pending = tuple(residue_transactions[0].iterdir())
        self.assertEqual(1, len(pending))
        self.assertEqual(
            f".{publication.CRATES_IO_PUBLICATION_JOURNAL_NAME}.pending-"
            f"{process.pid}",
            pending[0].name,
        )
        self.assertEqual(0o600, stat.S_IMODE(pending[0].stat().st_mode))
        self.assertEqual(1, pending[0].stat().st_nlink)

        self.assert_precommit_journal_residue_recovers_before_upload(
            residue_name
        )

    def test_sigkill_after_final_intent_only_reconciles_remote_state(self) -> None:
        ready = self.root / "journal-final.ready"
        journal_recorded_at = "2026-08-15T02:00:00Z"
        journal_clock = FixedClock(journal_recorded_at)
        source = """
import datetime as dt
import os
import pathlib
import signal
import sys

from crates_io_publication import (
    SourceIdentity,
    load_local_publication_evidence,
    write_upload_intent,
)

journal_root = pathlib.Path(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
intent_recorded_at = dt.datetime.strptime(
    sys.argv[11], "%Y-%m-%dT%H:%M:%SZ"
).replace(tzinfo=dt.UTC)
source = SourceIdentity(
    source_parent_commit=sys.argv[3],
    tag_commit=sys.argv[4],
    tag_tree=sys.argv[5],
    canonical_source_tree_sha256=sys.argv[6],
)
evidence = load_local_publication_evidence(
    source,
    pathlib.Path(sys.argv[7]),
    sys.argv[8],
    handoff_root=pathlib.Path(sys.argv[9]),
    source_tree_resolver=lambda _commit: sys.argv[10],
    source_transition_verifier=lambda _source, _path, _digest: None,
)
write_upload_intent(
    evidence,
    evidence.crates[0],
    journal_root=journal_root,
    clock=lambda: intent_recorded_at,
)
ready.write_bytes(b"ready")
os.chmod(ready, 0o600)
signal.pause()
"""
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                source,
                os.fspath(self.journal_root),
                os.fspath(ready),
                self.source.source_parent_commit,
                self.source.tag_commit,
                self.source.tag_tree,
                self.source.canonical_source_tree_sha256,
                os.fspath(self.handoff_manifest_path),
                self.handoff_manifest_sha256,
                os.fspath(self.handoff_root),
                self.handoff_source.source_tree,
                journal_recorded_at,
            ],
            cwd=pathlib.Path(__file__).resolve().parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        deadline = time.monotonic() + 10
        while not ready.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=1)
                self.fail(
                    "journal writer exited before final-intent window: "
                    f"status={process.returncode} stdout={stdout!r} stderr={stderr!r}"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate(timeout=5)
                self.fail("journal writer did not reach final-intent window")
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(-signal.SIGKILL, process.returncode)
        self.assertEqual(b"", stdout)
        self.assertEqual(b"", stderr)

        evidence = self.evidence()
        unresolved = publication.load_unresolved_upload_intents(
            evidence,
            journal_root=self.journal_root,
        )
        self.assertEqual(1, len(unresolved))
        final_transaction = unresolved[0].path.parent
        self.assertEqual(
            frozenset({publication.CRATES_IO_PUBLICATION_JOURNAL_NAME}),
            frozenset(path.name for path in final_transaction.iterdir()),
        )
        provider_calls = 0

        def unavailable_provider() -> str:
            nonlocal provider_calls
            provider_calls += 1
            raise RuntimeError("reconcile must not request a credential")

        def unexpected_upload(
            _package: publication.LocalCrate,
            *,
            credential: str,
        ) -> BoundedResult:
            del credential
            raise AssertionError("final upload intent must not be retried")

        registry = RegistryFixture(evidence.crates, published_count=10)
        values, writer = self.memory_writer()
        result = self.run_publication(
            mode="publish",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=journal_clock,
            receipt_writer=writer,
            journal_root=self.journal_root,
            execute_real_upload=True,
            irreversible_acknowledgement=(
                publication.REAL_UPLOAD_ACKNOWLEDGEMENT
            ),
            credential_provider=unavailable_provider,
            lock_factory=contextlib.nullcontext,
            upload_runner=unexpected_upload,
        )
        self.assertEqual(0, provider_calls)
        self.assertEqual((), result.upload_attempts)
        self.assertEqual(
            contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED,
            result.receipt["status"],
        )
        self.assertEqual(1, len(values))
        self.assertEqual(
            (),
            publication.load_unresolved_upload_intents(
                evidence,
                journal_root=self.journal_root,
            ),
        )

    def test_incomplete_journal_recovery_rejects_unsafe_residue_without_deletion(
        self,
    ) -> None:
        def altered_fstat(
            target: pathlib.Path,
            *,
            mode: int | None = None,
            uid: int | None = None,
        ) -> contextlib.AbstractContextManager[object]:
            target_inode = target.stat().st_ino
            real_fstat = os.fstat

            def inspect(descriptor: int) -> os.stat_result:
                metadata = real_fstat(descriptor)
                if metadata.st_ino != target_inode:
                    return metadata
                fields = list(metadata)
                if mode is not None:
                    fields[0] = mode
                if uid is not None:
                    fields[4] = uid
                return os.stat_result(fields)

            return mock.patch.object(publication.os, "fstat", side_effect=inspect)

        variants = (
            "wrong-pid",
            "symlink",
            "hardlink",
            "fifo",
            "directory",
            "wrong-mode",
            "wrong-owner",
            "device",
            "oversize",
        )
        for index, variant in enumerate(variants, start=1):
            with self.subTest(variant=variant):
                journal_root = self.root / f"unsafe-journal-{index}"
                journal_root.mkdir(mode=0o700)
                transaction = journal_root / "transaction.123-0"
                transaction.mkdir(mode=0o700)
                pending_name = (
                    f".{publication.CRATES_IO_PUBLICATION_JOURNAL_NAME}.pending-"
                    f"{'124' if variant == 'wrong-pid' else '123'}"
                )
                pending = transaction / pending_name
                patcher: contextlib.AbstractContextManager[object] = (
                    contextlib.nullcontext()
                )
                if variant == "symlink":
                    target = self.root / f"unsafe-target-{index}"
                    target.write_bytes(b"outside\n")
                    os.chmod(target, 0o600)
                    pending.symlink_to(target)
                elif variant == "hardlink":
                    target = self.root / f"unsafe-target-{index}"
                    target.write_bytes(b"linked\n")
                    os.chmod(target, 0o600)
                    os.link(target, pending)
                elif variant == "fifo":
                    os.mkfifo(pending, 0o600)
                    os.chmod(pending, 0o600)
                elif variant == "directory":
                    pending.mkdir(mode=0o700)
                else:
                    payload = (
                        b"x" * (256 * 1024 + 1)
                        if variant == "oversize"
                        else b"pending\n"
                    )
                    pending.write_bytes(payload)
                    os.chmod(pending, 0o644 if variant == "wrong-mode" else 0o600)
                    if variant == "wrong-owner":
                        patcher = altered_fstat(
                            pending,
                            uid=os.geteuid() + 1,
                        )
                    elif variant == "device":
                        patcher = altered_fstat(
                            pending,
                            mode=stat.S_IFCHR | 0o600,
                        )

                started = time.monotonic()
                with patcher, self.assertRaises(
                    publication.CratesIoPublicationError
                ):
                    publication._recover_incomplete_upload_journal_transactions(
                        journal_root
                    )
                self.assertLess(
                    time.monotonic() - started,
                    2,
                    "unsafe non-regular residue inspection blocked",
                )
                self.assertTrue(transaction.exists())
                self.assertTrue(os.path.lexists(pending))

    def test_final_plus_pending_journal_is_preserved_and_blocks_upload(self) -> None:
        self.journal_root.mkdir(mode=0o700)
        transaction = self.journal_root / "transaction.321-0"
        transaction.mkdir(mode=0o700)
        final_leaf = transaction / publication.CRATES_IO_PUBLICATION_JOURNAL_NAME
        final_leaf.write_bytes(b"{}\n")
        os.chmod(final_leaf, 0o600)
        pending = transaction / (
            f".{publication.CRATES_IO_PUBLICATION_JOURNAL_NAME}.pending-321"
        )
        pending.write_bytes(b"partial\n")
        os.chmod(pending, 0o600)
        provider_calls = 0
        upload_calls = 0

        def unexpected_provider() -> str:
            nonlocal provider_calls
            provider_calls += 1
            raise AssertionError("mixed journal must fail before credentials")

        def unexpected_upload(
            _package: publication.LocalCrate,
            *,
            credential: str,
        ) -> BoundedResult:
            nonlocal upload_calls
            del credential
            upload_calls += 1
            raise AssertionError("mixed journal must fail before upload")

        registry = RegistryFixture(self.evidence().crates)
        with self.assertRaises(publication.CratesIoPublicationError):
            self.run_publication(
                mode="publish",
                api_fetcher=registry.api,
                sparse_fetcher=registry.sparse,
                receipt_writer=self.memory_writer()[1],
                journal_root=self.journal_root,
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=unexpected_provider,
                lock_factory=contextlib.nullcontext,
                upload_runner=unexpected_upload,
            )
        self.assertEqual(0, provider_calls)
        self.assertEqual(0, upload_calls)
        self.assertTrue(final_leaf.exists())
        self.assertTrue(pending.exists())

    def test_incomplete_journal_recovery_rejects_resampling_races(self) -> None:
        for variant in ("inventory", "identity"):
            with self.subTest(variant=variant):
                journal_root = self.root / f"racing-journal-{variant}"
                journal_root.mkdir(mode=0o700)
                transaction = journal_root / "transaction.456-0"
                transaction.mkdir(mode=0o700)
                pending = transaction / (
                    f".{publication.CRATES_IO_PUBLICATION_JOURNAL_NAME}.pending-456"
                )
                pending.write_bytes(b"partial\n")
                os.chmod(pending, 0o600)
                displaced = journal_root / "displaced"
                real_open = os.open
                transaction_opens = 0

                def mutate_before_second_open(
                    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal transaction_opens
                    if path == transaction.name:
                        transaction_opens += 1
                        if transaction_opens == 2:
                            if variant == "inventory":
                                extra = transaction / "unexpected"
                                extra.write_bytes(b"race\n")
                                os.chmod(extra, 0o600)
                            else:
                                transaction.rename(displaced)
                                transaction.mkdir(mode=0o700)
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    publication.os,
                    "open",
                    side_effect=mutate_before_second_open,
                ), self.assertRaises(publication.CratesIoPublicationError):
                    publication._recover_incomplete_upload_journal_transactions(
                        journal_root
                    )
                if variant == "inventory":
                    self.assertTrue(transaction.exists())
                    self.assertTrue(pending.exists())
                    self.assertTrue((transaction / "unexpected").exists())
                else:
                    self.assertTrue(transaction.exists())
                    self.assertTrue(displaced.exists())
                    self.assertTrue((displaced / pending.name).exists())

    def test_credential_provider_exception_is_redacted(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates)
        secret = "cio_provider_secret_123456"

        def provider() -> str:
            raise RuntimeError(secret)

        with self.assertRaises(publication.CratesIoPublicationError) as raised:
            self.run_publication(
                mode="publish",
                api_fetcher=registry.api,
                sparse_fetcher=registry.sparse,
                receipt_writer=self.memory_writer()[1],
                journal_root=self.journal_root,
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=provider,
                lock_factory=contextlib.nullcontext,
                upload_runner=registry.upload,
            )
        rendered = "".join(
            traceback.format_exception(
                type(raised.exception),
                raised.exception,
                raised.exception.__traceback__,
            )
        )
        self.assertNotIn(secret, rendered)

    def test_nonzero_upload_is_accepted_only_after_exact_remote_observation(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates)
        calls: list[str] = []

        def nonzero_upload(
            package: publication.LocalCrate,
            *,
            credential: str,
        ) -> BoundedResult:
            self.assertEqual("cio_fixture_token_123456789", credential)
            calls.append(package.name)
            if len(calls) == 1:
                registry.published.add(package.name)
            return BoundedResult(returncode=17)

        values, writer = self.memory_writer()
        with self.assertRaises(
            publication.CratesIoUploadOutcomeUnknownError
        ) as raised:
            self.run_publication(
                mode="publish",
                api_fetcher=registry.api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
                sleeper=lambda _seconds: None,
                receipt_writer=writer,
                journal_root=self.journal_root,
                execute_real_upload=True,
                irreversible_acknowledgement=(
                    publication.REAL_UPLOAD_ACKNOWLEDGEMENT
                ),
                credential_provider=lambda: "cio_fixture_token_123456789",
                lock_factory=contextlib.nullcontext,
                upload_runner=nonzero_upload,
                poll_attempts=1,
                poll_interval_seconds=0,
            )
        self.assertEqual(list(contract.PUBLISHABLE_CRATES[:2]), calls)
        self.assertEqual(
            contract.CRATE_STATUS_PUBLISHED_VERIFIED,
            raised.exception.verified_receipt["crates"][0]["state"],
        )
        self.assertEqual(
            contract.CRATE_STATUS_ABSENT,
            raised.exception.verified_receipt["crates"][1]["state"],
        )
        self.assertGreaterEqual(len(values), 2)

    def test_api_json_and_http_boundaries_reject_hostile_output(self) -> None:
        package = self.evidence().crates[0]
        registry = RegistryFixture((package,), published_count=1)

        def duplicate_api(
            url: str, **_kwargs: object
        ) -> publication.HttpResponse:
            body = (
                b'{"version":{"num":"0.1.4","num":"0.1.4",'
                + f'"checksum":"{package.sha256}","yanked":false}}\n'.encode(
                    "ascii"
                )
            )
            return publication.HttpResponse(200, url, body)

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "duplicate JSON key"
        ):
            publication.observe_remote_crate(
                package,
                api_fetcher=duplicate_api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
            )

        def oversized_api(
            url: str, **_kwargs: object
        ) -> publication.HttpResponse:
            return publication.HttpResponse(
                200, url, b"x" * (publication.MAX_API_BYTES + 1)
            )

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "byte limit"
        ):
            publication.observe_remote_crate(
                package,
                api_fetcher=oversized_api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
            )

        def redirected_api(
            url: str, **_kwargs: object
        ) -> publication.HttpResponse:
            return publication.HttpResponse(200, f"{url}?redirected=1", b"{}")

        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "redirected"
        ):
            publication.observe_remote_crate(
                package,
                api_fetcher=redirected_api,
                sparse_fetcher=registry.sparse,
                clock=FixedClock(),
            )

    def test_https_get_rejects_proxy_and_ca_overrides_before_network(self) -> None:
        url = f"{publication.CRATES_IO_REGISTRY}/api/v1/crates/example/0.1.0"
        for name, value in (
            ("HTTPS_PROXY", "/fixture/override"),
            ("SSL_CERT_FILE", "/fixture/override"),
            ("CURL_CA_BUNDLE", "/fixture/override"),
            ("HTTPS_PROXY", ""),
        ):
            with (
                self.subTest(name=name, value=value),
                mock.patch.dict(os.environ, {name: value}, clear=True),
                mock.patch.object(
                    publication.ssl,
                    "create_default_context",
                ) as create_context,
                mock.patch.object(
                    publication.urllib.request,
                    "build_opener",
                ) as build_opener,
                self.assertRaisesRegex(
                    publication.CratesIoPublicationError,
                    "proxy or TLS trust overrides",
                ),
            ):
                publication._https_get(
                    url,
                    timeout_seconds=1,
                    maximum_bytes=1024,
                )
            create_context.assert_not_called()
            build_opener.assert_not_called()

    def test_https_get_uses_direct_tls_and_exact_url(self) -> None:
        url = f"{publication.CRATES_IO_REGISTRY}/api/v1/crates/example/0.1.0"

        class Response:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_arguments: object) -> None:
                return None

            def geturl(self) -> str:
                return url

            def read(self, _maximum: int) -> bytes:
                body = getattr(self, "_body", b"{}")
                self._body = b""
                return body

        class Opener:
            def open(
                self,
                request: object,
                *,
                timeout: int,
            ) -> Response:
                self.request = request
                self.timeout = timeout
                return Response()

        tls_context = mock.Mock(
            check_hostname=True,
            verify_mode=publication.ssl.CERT_REQUIRED,
        )
        opener = Opener()
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                publication.ssl,
                "create_default_context",
                return_value=tls_context,
            ) as create_context,
            mock.patch.object(
                publication.urllib.request,
                "build_opener",
                return_value=opener,
            ) as build_opener,
        ):
            response = publication._https_get(
                url,
                timeout_seconds=7,
                maximum_bytes=1024,
            )

        self.assertEqual(publication.HttpResponse(200, url, b"{}"), response)
        create_context.assert_called_once_with(
            purpose=publication.ssl.Purpose.SERVER_AUTH
        )
        handlers = build_opener.call_args.args
        self.assertEqual({}, handlers[0].proxies)
        self.assertIs(tls_context, handlers[1]._context)
        self.assertIsInstance(handlers[2], publication._RejectRedirectHandler)
        self.assertEqual(7, opener.timeout)

    def test_https_get_rejects_host_drift_and_redirects(self) -> None:
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "official crates.io HTTPS origins",
        ):
            publication._https_get(
                "https://crates.io.example/api/v1/crates/example/0.1.0",
                timeout_seconds=1,
                maximum_bytes=1024,
            )
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "redirected",
        ):
            publication._RejectRedirectHandler().redirect_request(
                mock.Mock(),
                mock.Mock(),
                302,
                "Found",
                {},
                "https://example.invalid/forged",
            )

    def test_symlink_hardlink_and_outside_paths_fail(self) -> None:
        first = self.handoff_manifest_path.parent / self.package_paths[0].name
        original = first.read_bytes()
        first.unlink()
        outside = self.root / "outside.crate"
        outside.write_bytes(original)
        os.chmod(outside, 0o600)
        first.symlink_to(outside)
        with self.assertRaises(publication.CratesIoPublicationError):
            self.evidence()

        first.unlink()
        os.link(outside, first)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "cannot safely read"
        ):
            self.evidence()

        first.unlink()
        first.write_bytes(original)
        os.chmod(first, 0o600)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "fixed transaction shape",
        ):
            publication.load_local_publication_evidence(
                self.source,
                outside,
                self.handoff_manifest_sha256,
                handoff_root=self.handoff_root,
                source_tree_resolver=lambda _commit: self.handoff_source.source_tree,
                source_transition_verifier=lambda _source, _path, _digest: None,
            )

    def test_private_receipt_is_no_replace_and_writer_fault_cleans_staging(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates, published_count=10)
        result = self.run_publication(
            mode="verify",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=FixedClock(),
            write_verify_receipt=False,
        )
        path, digest = publication.write_publication_receipt(
            result.receipt, receipt_root=self.receipt_root
        )
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(1, path.stat().st_nlink)
        loaded = publication.load_previous_receipt(
            path, safe_root=self.receipt_root
        )
        self.assertEqual(result.receipt, loaded)

        fault_root = self.root / "fault-receipts"

        def fail_write(_descriptor: int, _payload: bytes) -> int:
            raise OSError("injected writer failure")

        with mock.patch.object(receipt_io.os, "write", fail_write):
            with self.assertRaises(receipt_io.PublicationReceiptIOError):
                publication.write_publication_receipt(
                    result.receipt, receipt_root=fault_root
                )
        self.assertEqual(
            [],
            list(
                fault_root.glob(
                    "*/" + publication.CRATES_IO_PUBLICATION_RECEIPT_NAME
                )
            ),
        )
        self.assertEqual([], list(fault_root.glob("*/.*.pending-*")))
        self.assertEqual([], list(fault_root.glob("transaction.*")))

    def test_handoff_postcommit_fault_reports_committed_manifest(self) -> None:
        handoff_root = self.root / "committed-handoffs"
        original_verify = publication.verify_exact_directory_inventory_at

        def fail_after_commit(
            directory_fd: int,
            expected_entries: frozenset[str],
            *,
            label: str,
        ) -> frozenset[str]:
            if label == "committed Rust package handoff transaction":
                raise receipt_io.PublicationReceiptIOError(
                    "injected postcommit inventory failure"
                )
            return original_verify(
                directory_fd, expected_entries, label=label
            )

        with (
            mock.patch.object(
                publication,
                "verify_exact_directory_inventory_at",
                side_effect=fail_after_commit,
            ),
            self.assertRaises(receipt_io.PublicationReceiptCommittedError) as raised,
        ):
            publication.finalize_rust_package_handoff(
                self.staging_root,
                staging_device=self.staging_device,
                staging_inode=self.staging_inode,
                handoff_root=handoff_root,
                source_inspector=lambda: self.handoff_source,
            )
        self.assertEqual("committed", raised.exception.visibility)
        self.assertIsNotNone(raised.exception.path)
        self.assertRegex(raised.exception.digest or "", r"^[0-9a-f]{64}$")
        self.assertTrue(raised.exception.path.is_file())

    def test_handoff_precommit_writer_fault_never_creates_commit_leaf(self) -> None:
        handoff_root = self.root / "failed-handoffs"

        def fail_write(_descriptor: int, _payload: bytes) -> int:
            raise OSError("injected handoff writer failure")

        with (
            mock.patch.object(receipt_io.os, "write", fail_write),
            self.assertRaises(receipt_io.PublicationReceiptIOError),
        ):
            publication.finalize_rust_package_handoff(
                self.staging_root,
                staging_device=self.staging_device,
                staging_inode=self.staging_inode,
                handoff_root=handoff_root,
                source_inspector=lambda: self.handoff_source,
            )
        self.assertEqual(
            [],
            list(
                handoff_root.glob(
                    "*/" + publication.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
                )
            ),
        )
        self.assertEqual([], list(handoff_root.glob("*/.*.pending-*")))

    def assert_handoff_signal_window(self, phase: str) -> None:
        completed, handoff_root = self.run_handoff_signal_window(phase)
        self.assertEqual(b"", completed.stdout)
        self.assertFalse(self.staging_root.exists())
        manifests = list(
            handoff_root.glob(
                "*/" + publication.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
            )
        )
        if phase == "precommit":
            self.assertEqual(128 + signal.SIGTERM, completed.returncode)
            self.assertEqual(b"", completed.stderr)
            self.assertEqual([], manifests)
            return

        self.assertEqual(125, completed.returncode)
        self.assertEqual(1, len(manifests))
        diagnostic = completed.stderr.decode("ascii")
        self.assertNotIn("RUST_PACKAGE_HANDOFF_PASS", diagnostic)
        self.assertEqual(1, diagnostic.count("RUST_PACKAGE_HANDOFF_COMMITTED"))
        self.assertNotIn(os.fspath(self.root), diagnostic)
        match = re.fullmatch(
            r"error: RUST_PACKAGE_HANDOFF_COMMITTED "
            r"visibility=committed "
            r"path=target/test-rust-handoffs/"
            r"transaction\.[1-9][0-9]*-[0-9a-f]{32}/"
            r"rust-package-handoff\.json "
            r"sha256=([0-9a-f]{64})\n",
            diagnostic,
        )
        self.assertIsNotNone(match)
        self.assertEqual(
            hashlib.sha256(manifests[0].read_bytes()).hexdigest(),
            match.group(1),
        )

    def test_handoff_precommit_signal_never_commits(self) -> None:
        self.assert_handoff_signal_window("precommit")

    def test_handoff_visibility_signal_emits_only_committed_marker(self) -> None:
        self.assert_handoff_signal_window("visibility")

    def test_handoff_postcommit_signal_emits_only_committed_marker(self) -> None:
        self.assert_handoff_signal_window("postcommit")

    def test_handoff_success_subprocess_emits_only_pass_marker(self) -> None:
        completed, handoff_root = self.run_handoff_signal_window("success")
        self.assertEqual(0, completed.returncode)
        self.assertEqual(b"", completed.stdout)
        diagnostic = completed.stderr.decode("ascii")
        self.assertEqual(1, diagnostic.count("RUST_PACKAGE_HANDOFF_PASS"))
        self.assertNotIn("RUST_PACKAGE_HANDOFF_COMMITTED", diagnostic)
        self.assertNotIn(os.fspath(self.root), diagnostic)
        manifests = list(
            handoff_root.glob(
                "*/" + publication.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
            )
        )
        self.assertEqual(1, len(manifests))

    def test_prior_receipt_symlink_and_hardlink_fail(self) -> None:
        evidence = self.evidence()
        registry = RegistryFixture(evidence.crates, published_count=1)
        result = self.run_publication(
            mode="verify",
            api_fetcher=registry.api,
            sparse_fetcher=registry.sparse,
            clock=FixedClock(),
            write_verify_receipt=False,
        )
        path, _digest = publication.write_publication_receipt(
            result.receipt, receipt_root=self.receipt_root
        )
        link_transaction = self.receipt_root / "transaction.link"
        link_transaction.mkdir(mode=0o700)
        symlink = link_transaction / publication.CRATES_IO_PUBLICATION_RECEIPT_NAME
        symlink.symlink_to(path)
        with self.assertRaises(publication.CratesIoPublicationError):
            publication.load_previous_receipt(
                symlink, safe_root=self.receipt_root
            )

        symlink.unlink()
        os.link(path, symlink)
        with self.assertRaises(publication.CratesIoPublicationError):
            publication.load_previous_receipt(
                symlink, safe_root=self.receipt_root
            )

    def test_production_lock_is_persistent_exclusive_and_outside_worktrees(self) -> None:
        state_root = self.production_state_root
        factory = publication.production_lock_factory(state_root)
        lock_path = state_root / publication.CRATES_IO_PUBLICATION_LOCK_NAME

        with factory():
            self.assertTrue(lock_path.is_file())
            self.assertEqual(0o600, stat.S_IMODE(lock_path.stat().st_mode))
            self.assertEqual(1, lock_path.stat().st_nlink)

            def contend() -> None:
                with factory():
                    raise AssertionError("concurrent lock acquisition succeeded")

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(contend)
                with self.assertRaises(
                    publication.CratesIoPublicationLockHeldError
                ):
                    future.result(timeout=5)
        inode = lock_path.stat().st_ino
        with factory():
            self.assertEqual(inode, lock_path.stat().st_ino)

        current_checkout = self.root / "current-checkout"
        second_checkout = self.root / "second-checkout"
        current_checkout.mkdir(mode=0o700)
        second_checkout.mkdir(mode=0o700)
        with mock.patch.object(
            publication,
            "_registered_git_worktree_roots",
            return_value=(current_checkout, second_checkout),
        ):
            for checkout in (current_checkout, second_checkout):
                private_root = checkout / ".q-periapt"
                private_root.mkdir(mode=0o700)
                state_parent = private_root / "publication-state"
                state_parent.mkdir(mode=0o700)
                state_inside = state_parent / "crates.io-v0.1.4"
                state_inside.mkdir(mode=0o700)
                with (
                    self.subTest(checkout=checkout),
                    mock.patch.object(
                        publication.pwd,
                        "getpwuid",
                        return_value=mock.Mock(pw_dir=os.fspath(checkout)),
                    ),
                    self.assertRaisesRegex(
                        publication.CratesIoPublicationError,
                        "outside every registered Git worktree",
                    ),
                ):
                    publication._validated_publication_state_root(state_inside)

        alternate_root = self.root / "alternate-external-state"
        alternate_root.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "fixed account publication root",
        ):
            publication._validated_publication_state_root(alternate_root)

        with mock.patch.dict(
            os.environ,
            {"HOME": os.fspath(alternate_root)},
        ):
            self.assertEqual(
                state_root,
                publication._validated_publication_state_root(state_root),
            )

    def test_registered_worktree_inventory_is_nul_delimited_and_exact(self) -> None:
        current = publication.REPOSITORY_ROOT
        second = self.root / "registered-second-worktree"
        payload = (
            f"worktree {current}\0HEAD {'1' * 40}\0branch refs/heads/main\0\0"
            f"worktree {second}\0HEAD {'2' * 40}\0detached\0\0"
        ).encode("utf-8")
        with mock.patch.object(publication, "run_git_bytes", return_value=payload):
            self.assertEqual(
                (current, second), publication._registered_git_worktree_roots()
            )
        for malformed in (b"", b"worktree relative\0\0"):
            with (
                self.subTest(malformed=malformed),
                mock.patch.object(
                    publication, "run_git_bytes", return_value=malformed
                ),
                self.assertRaises(publication.CratesIoPublicationError),
            ):
                publication._registered_git_worktree_roots()

    def test_publication_account_home_rejects_foreign_owned_ancestor(self) -> None:
        foreign_ancestor = self.account_home.parent
        original_lstat = pathlib.Path.lstat

        def lstat_with_foreign_ancestor(path: pathlib.Path) -> os.stat_result:
            metadata = original_lstat(path)
            if path != foreign_ancestor:
                return metadata
            fields = list(metadata)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)

        with (
            mock.patch.object(
                pathlib.Path,
                "lstat",
                autospec=True,
                side_effect=lstat_with_foreign_ancestor,
            ),
            self.assertRaisesRegex(
                publication.CratesIoPublicationError,
                "ancestry is not trusted",
            ),
        ):
            publication._publication_account_home()

    def test_publication_account_home_rejects_world_writable_ancestor(
        self,
    ) -> None:
        writable_ancestor = self.account_home.parent
        original_lstat = pathlib.Path.lstat

        def lstat_with_writable_ancestor(
            path: pathlib.Path,
        ) -> os.stat_result:
            metadata = original_lstat(path)
            if path != writable_ancestor:
                return metadata
            fields = list(metadata)
            fields[0] |= 0o002
            return os.stat_result(fields)

        with (
            mock.patch.object(
                pathlib.Path,
                "lstat",
                autospec=True,
                side_effect=lstat_with_writable_ancestor,
            ),
            self.assertRaisesRegex(
                publication.CratesIoPublicationError,
                "ancestry is not trusted",
            ),
        ):
            publication._publication_account_home()

    def test_production_lock_rejects_symlink_root_and_lock_hardlink(self) -> None:
        state_root = self.production_state_root
        alias = self.root / "state-alias"
        alias.symlink_to(state_root, target_is_directory=True)
        with self.assertRaises(publication.CratesIoPublicationError):
            publication.production_lock_factory(alias)

        symlink_target = self.root / "state-symlink-target"
        symlink_target.mkdir(mode=0o700)
        state_root.rmdir()
        state_root.symlink_to(symlink_target, target_is_directory=True)
        with self.assertRaises(publication.CratesIoPublicationError):
            publication.production_lock_factory(state_root)
        state_root.unlink()
        state_root.mkdir(mode=0o700)

        outside_lock = self.root / "outside-lock"
        outside_lock.write_bytes(b"")
        os.chmod(outside_lock, 0o600)
        lock_path = state_root / publication.CRATES_IO_PUBLICATION_LOCK_NAME
        lock_path.symlink_to(
            outside_lock
        )
        with self.assertRaises(publication.CratesIoPublicationError):
            with publication.production_lock_factory(state_root)():
                pass
        lock_path.unlink()

        factory = publication.production_lock_factory(state_root)
        with factory():
            pass
        os.link(lock_path, self.root / "lock-hardlink")
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "single-link"
        ):
            with factory():
                pass

    def test_production_uploader_consumes_only_exact_stdin_bytes(self) -> None:
        package = self.evidence().crates[0]
        state_root = self.production_state_root
        uploader_path = (
            state_root / publication.CRATES_IO_PUBLICATION_UPLOADER_NAME
        )
        uploader_path.write_text(
            "\n".join(
                (
                    "#!/usr/bin/python3",
                    "import hashlib, sys",
                    "arguments = sys.argv[1:]",
                    "if arguments[0] != '--crate-stdin' or '--crate-file' in arguments:",
                    "    raise SystemExit(11)",
                    "def field(name):",
                    "    index = arguments.index(name)",
                    "    return arguments[index + 1]",
                    "payload = sys.stdin.buffer.read()",
                    "if len(payload) != int(field('--size')):",
                    "    raise SystemExit(12)",
                    "if hashlib.sha256(payload).hexdigest() != field('--sha256'):",
                    "    raise SystemExit(13)",
                    "raise SystemExit(0)",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(uploader_path, 0o700)
        uploader = publication.production_upload_runner(
            uploader_path, state_root=state_root
        )
        result = uploader(package, credential="cio_fixture_token_123456789")
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"", result.stdout)

        outside = self.root / "outside-uploader"
        outside.write_bytes(uploader_path.read_bytes())
        os.chmod(outside, 0o700)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "fixed publication uploader path"
        ):
            publication.production_upload_runner(outside, state_root=state_root)

        alternate = state_root / "alternate-uploader"
        alternate.write_bytes(uploader_path.read_bytes())
        os.chmod(alternate, 0o700)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "fixed publication uploader path",
        ):
            publication.production_upload_runner(alternate, state_root=state_root)

        nested_root = state_root / "tools"
        nested_root.mkdir(mode=0o700)
        nested = nested_root / "nested-uploader"
        nested.write_bytes(uploader_path.read_bytes())
        os.chmod(nested, 0o700)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError, "fixed publication uploader path"
        ):
            publication.production_upload_runner(nested, state_root=state_root)

        with self.assertRaises(publication.CratesIoPublicationError):
            publication.production_upload_runner(
                state_root, state_root=state_root
            )

        hardlink = state_root / "hardlinked-uploader"
        os.link(uploader_path, hardlink)
        with self.assertRaisesRegex(
            publication.CratesIoPublicationError,
            "single-link",
        ):
            publication.production_upload_runner(
                uploader_path,
                state_root=state_root,
            )
        hardlink.unlink()

        uploader_path.unlink()
        uploader_path.symlink_to(outside)
        with self.assertRaises(publication.CratesIoPublicationError):
            publication.production_upload_runner(
                uploader_path,
                state_root=state_root,
            )

    def test_real_publish_cli_requires_explicit_state_root(self) -> None:
        source_path = self.root / "source-identity.json"
        source_path.write_bytes(_json(self.source.document()))
        os.chmod(source_path, 0o600)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = publication._main(
                [
                    "publish",
                    os.fspath(source_path),
                    os.fspath(self.handoff_manifest_path),
                    self.handoff_manifest_sha256,
                    "--execute-real-upload",
                    "--acknowledge-irreversible-publish",
                ]
            )
        self.assertEqual(1, status)
        self.assertIn("explicit --state-root", stderr.getvalue())

    def test_publish_cli_rejects_alternate_authority_confirmations_before_io(
        self,
    ) -> None:
        state_root = self.production_state_root
        uploader_path = (
            state_root / publication.CRATES_IO_PUBLICATION_UPLOADER_NAME
        )
        cases = (
            (
                "state-root",
                self.root / "alternate-state-root",
                uploader_path,
                "publication state root confirmation",
            ),
            (
                "uploader",
                state_root,
                state_root / "alternate-uploader",
                "publication uploader confirmation",
            ),
        )
        for label, supplied_root, supplied_uploader, expected_error in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(publication, "_source_from_json") as read_source,
                mock.patch.object(
                    publication, "_validated_publication_state_root"
                ) as validate_root,
                mock.patch.object(publication, "production_lock_factory") as make_lock,
                mock.patch.object(
                    publication, "production_upload_runner"
                ) as make_uploader,
                mock.patch.object(
                    publication, "run_publication_transaction"
                ) as run_transaction,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                status = publication._main(
                    [
                        "publish",
                        os.fspath(self.root / "must-not-be-read.json"),
                        os.fspath(self.handoff_manifest_path),
                        self.handoff_manifest_sha256,
                        "--state-root",
                        os.fspath(supplied_root),
                        "--uploader-command",
                        os.fspath(supplied_uploader),
                        "--execute-real-upload",
                        "--acknowledge-irreversible-publish",
                    ]
                )
            self.assertEqual(1, status)
            self.assertIn(expected_error, stderr.getvalue())
            read_source.assert_not_called()
            validate_root.assert_not_called()
            make_lock.assert_not_called()
            make_uploader.assert_not_called()
            run_transaction.assert_not_called()

    def test_publish_cli_rejects_handoff_confirmation_before_publication_io(
        self,
    ) -> None:
        source_path = self.root / "source-identity.json"
        source_path.write_bytes(_json(self.source.document()))
        os.chmod(source_path, 0o600)
        state_root = self.production_state_root
        uploader_path = (
            state_root / publication.CRATES_IO_PUBLICATION_UPLOADER_NAME
        )
        selected = self.cli_selected_handoff()
        cases = (
            (
                "path",
                self.root / "alternate-handoff.json",
                selected.sha256,
            ),
            (
                "digest",
                selected.path,
                "f" * 64,
            ),
        )
        for label, supplied_path, supplied_sha256 in cases:
            with (
                self.subTest(label=label),
                mock.patch.object(
                    publication,
                    "_results_selected_handoff",
                    return_value=selected,
                ),
                mock.patch.object(
                    publication, "_validated_publication_state_root"
                ) as validate_root,
                mock.patch.object(publication, "production_lock_factory") as make_lock,
                mock.patch.object(
                    publication, "production_upload_runner"
                ) as make_uploader,
                mock.patch.object(
                    publication, "run_publication_transaction"
                ) as run_transaction,
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                status = publication._main(
                    [
                        "publish",
                        os.fspath(source_path),
                        os.fspath(supplied_path),
                        supplied_sha256,
                        "--state-root",
                        os.fspath(state_root),
                        "--uploader-command",
                        os.fspath(uploader_path),
                        "--execute-real-upload",
                        "--acknowledge-irreversible-publish",
                    ]
                )
            self.assertEqual(1, status)
            self.assertIn("differs from results commit R", stderr.getvalue())
            validate_root.assert_not_called()
            make_lock.assert_not_called()
            make_uploader.assert_not_called()
            run_transaction.assert_not_called()

    def test_real_publish_cli_passes_derived_authority_to_lock_and_uploader(
        self,
    ) -> None:
        source_path = self.root / "source-identity.json"
        source_path.write_bytes(_json(self.source.document()))
        os.chmod(source_path, 0o600)
        state_root = self.production_state_root
        uploader_path = (
            state_root / publication.CRATES_IO_PUBLICATION_UPLOADER_NAME
        )
        uploader_path.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
        os.chmod(uploader_path, 0o700)
        lock_factory = mock.Mock()
        uploader = mock.Mock()
        with (
            mock.patch.object(
                publication,
                "production_lock_factory",
                return_value=lock_factory,
            ) as make_lock,
            mock.patch.object(
                publication,
                "production_upload_runner",
                return_value=uploader,
            ) as make_uploader,
            mock.patch.object(
                publication,
                "run_publication_transaction",
                side_effect=publication.CratesIoPublicationError(
                    "stopped before any upload"
                ),
            ),
            mock.patch.object(
                publication,
                "_results_selected_handoff",
                return_value=self.cli_selected_handoff(),
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status = publication._main(
                [
                    "publish",
                    os.fspath(source_path),
                    os.fspath(self.handoff_manifest_path),
                    self.handoff_manifest_sha256,
                    "--state-root",
                    os.fspath(state_root),
                    "--uploader-command",
                    os.fspath(uploader_path),
                    "--execute-real-upload",
                    "--acknowledge-irreversible-publish",
                ]
            )
        self.assertEqual(1, status)
        make_lock.assert_called_once_with(state_root)
        make_uploader.assert_called_once_with(
            uploader_path,
            state_root=state_root,
        )

    def test_verify_cli_marker_contains_controlled_receipt_path_and_digest(self) -> None:
        source_path = self.root / "source-identity.json"
        source_path.write_bytes(_json(self.source.document()))
        os.chmod(source_path, 0o600)
        digest = "a" * 64
        receipt_path = (
            publication.CRATES_IO_PUBLICATION_RECEIPT_ROOT
            / "transaction.1-0"
            / publication.CRATES_IO_PUBLICATION_RECEIPT_NAME
        )
        handoff_marker = pathlib.Path(
            "target/qperiapt-rust-package-handoffs/"
            "transaction.1-" + "c" * 32
        ) / publication.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
        selected_handoff = publication.ResultsSelectedHandoff(
            path=publication.REPOSITORY_ROOT / handoff_marker,
            relative_path=pathlib.PurePosixPath(handoff_marker.as_posix()),
            sha256=self.handoff_manifest_sha256,
        )
        result = publication.PublicationRun(
            mode="verify",
            receipt={"status": contract.PUBLICATION_STATUS_PARTIAL},
            written_receipts=(
                publication.WrittenReceipt(path=receipt_path, sha256=digest),
            ),
            upload_attempts=(),
            planned_crates=contract.PUBLISHABLE_CRATES,
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(
                publication, "run_publication_transaction", return_value=result
            ) as run_transaction,
            mock.patch.object(
                publication,
                "_results_selected_handoff",
                return_value=selected_handoff,
            ),
            mock.patch.object(
                publication,
                "_verified_cli_receipt",
                side_effect=lambda written: written,
            ),
            contextlib.redirect_stdout(stdout),
        ):
            status = publication._main(
                [
                    "verify",
                    os.fspath(source_path),
                    os.fspath(handoff_marker),
                    self.handoff_manifest_sha256,
                ]
            )
        self.assertEqual(0, status)
        self.assertEqual(selected_handoff.path, run_transaction.call_args.args[1])
        self.assertEqual(selected_handoff.sha256, run_transaction.call_args.args[2])
        self.assertEqual(
            "CRATES_IO_PUBLICATION_VERIFY_PASS version=0.1.4 status=partial "
            "receipt_path=target/qperiapt-crates-io-publication-receipts/"
            "transaction.1-0/crates-io-v0.1.4-publication-receipt.json "
            f"receipt_sha256={digest} upload=not-attempted\n",
            stdout.getvalue(),
        )

    def test_cli_postwriter_path_failure_is_generic_and_redacted(self) -> None:
        source_path = self.root / "source-identity.json"
        source_path.write_bytes(_json(self.source.document()))
        os.chmod(source_path, 0o600)
        hostile = self.root / "secret-replaced-receipt.json"
        result = publication.PublicationRun(
            mode="verify",
            receipt={"status": contract.PUBLICATION_STATUS_PARTIAL},
            written_receipts=(
                publication.WrittenReceipt(path=hostile, sha256="b" * 64),
            ),
            upload_attempts=(),
            planned_crates=contract.PUBLISHABLE_CRATES,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                publication, "run_publication_transaction", return_value=result
            ),
            mock.patch.object(
                publication,
                "_results_selected_handoff",
                return_value=self.cli_selected_handoff(),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = publication._main(
                [
                    "verify",
                    os.fspath(source_path),
                    os.fspath(self.handoff_manifest_path),
                    self.handoff_manifest_sha256,
                ]
            )
        self.assertEqual(1, status)
        self.assertEqual("", stdout.getvalue())
        self.assertNotIn(os.fspath(hostile), stderr.getvalue())
        self.assertEqual(
            "error: publication output could not be safely finalized\n",
            stderr.getvalue(),
        )
        self.assertEqual(
            "crates.io publication command failed safely",
            publication._safe_cli_error_message(
                publication.CratesIoPublicationError(os.fspath(hostile))
            ),
        )

    def test_cli_committed_writer_error_is_structured_and_path_redacted(self) -> None:
        source_path = self.root / "source-identity.json"
        source_path.write_bytes(_json(self.source.document()))
        os.chmod(source_path, 0o600)
        hostile = self.root / "secret-committed-path.json"
        committed = receipt_io.PublicationReceiptCommittedError(
            "hostile path must not be rendered",
            leaf=publication.CRATES_IO_PUBLICATION_RECEIPT_NAME,
            digest="d" * 64,
            path=hostile,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                publication,
                "run_publication_transaction",
                side_effect=committed,
            ),
            mock.patch.object(
                publication,
                "_results_selected_handoff",
                return_value=self.cli_selected_handoff(),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = publication._main(
                [
                    "verify",
                    os.fspath(source_path),
                    os.fspath(self.handoff_manifest_path),
                    self.handoff_manifest_sha256,
                ]
            )
        self.assertEqual(125, status)
        self.assertEqual("", stdout.getvalue())
        self.assertNotIn(os.fspath(hostile), stderr.getvalue())
        self.assertEqual(
            "error: publication receipt committed but command did not complete "
            "visibility=committed path=unavailable sha256="
            + "d" * 64
            + "\n",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
