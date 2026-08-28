#!/usr/bin/env python3
"""Direct state, projection, and remote-receipt tests for Apple 0.1.4."""

from __future__ import annotations

import ast
import copy
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import apple_release_verification as verification
import apple_stable_publication as publication
import apple_distribution
import apple_publication_contract as apple_contract
import crates_io_publication_contract as crates_contract
import platform_publication_contract
import publication_receipt_io as receipt_io
import release_publication_contract
from test_release_publication_contract import (
    pending_manifest_fixture,
    rebind_rust_publish_source,
    rebind_stable_current_source,
)


SOURCE_COMMIT = "1" * 40
VERIFIER_COMMIT = "2" * 40
TAG_OBJECT = "3" * 40
TAG_COMMIT = "4" * 40
TAG_TREE = "5" * 40
SOURCE_DIGEST = "6" * 64


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


class AppleStablePublicationTests(unittest.TestCase):
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

        self.completion_root = self.target / "qperiapt-apple-release-worktrees"
        self.completion_root.mkdir(mode=0o700)
        os.chmod(self.completion_root, 0o700)
        self.completion_transaction = self.completion_root / SOURCE_COMMIT
        self.completion_transaction.mkdir(mode=0o700)
        os.chmod(self.completion_transaction, 0o700)
        self.completion = (
            self.completion_transaction / publication.COMPLETION_LEDGER_NAME
        )

        self.public_root = self.target / "qperiapt-swift-xcframework"
        self.public_root.mkdir(mode=0o755)
        os.chmod(self.public_root, 0o755)
        self.public_distribution = (
            self.public_root / publication.APPLE_PUBLIC_DISTRIBUTION_NAME
        )
        self.public_distribution.mkdir(mode=0o755)
        os.chmod(self.public_distribution, 0o755)
        xcframework = self.public_distribution / "CQPeriapt.xcframework"
        xcframework.mkdir(mode=0o755)
        os.chmod(xcframework, 0o755)
        self.asset_bytes = {
            name: f"exact fixture bytes for {name}\n".encode("ascii")
            for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES
        }
        self.asset_hashes = {
            name: hashlib.sha256(data).hexdigest()
            for name, data in self.asset_bytes.items()
        }
        for name, data in self.asset_bytes.items():
            path = self.public_distribution / name
            path.write_bytes(data)
            os.chmod(path, 0o644)

        self.distribution = {
            "apple_distribution_evidence_sha256": self.asset_hashes[
                apple_distribution.APPLE_DISTRIBUTION_NAME
            ],
            "artifact_path": apple_distribution.XCFRAMEWORK_ZIP_NAME,
            "artifact_sha256": self.asset_hashes[
                apple_distribution.XCFRAMEWORK_ZIP_NAME
            ],
            "artifact_size": len(
                self.asset_bytes[apple_distribution.XCFRAMEWORK_ZIP_NAME]
            ),
            "checksums_sha256": self.asset_hashes[
                apple_distribution.SHA256SUMS_NAME
            ],
            "distribution_signed": True,
            "immutable_release": False,
            "manifest_sha256": self.asset_hashes[
                apple_distribution.MANIFEST_NAME
            ],
            "notarization_applicability": "not_applicable_static_sdk_payload",
            "notarized": False,
            "origin_signature_certificate_sha256": (
                publication.APPLE_EXPECTED_CERTIFICATE_SHA256
            ),
            "origin_signature_identity_class": "Developer ID Application",
            "origin_signature_team_id": publication.APPLE_EXPECTED_TEAM_ID,
            "public_release": False,
            # The receipt's distribution cross-links to the active
            # apple_v0_1_4 contract identity.  stage 4 bumps
            # apple_distribution's producer literals to the same values.
            "release_revision": apple_contract.APPLE_V0_1_4_IDENTITY[
                "distribution_revision"
            ],
            "release_tag": apple_contract.APPLE_V0_1_4_IDENTITY[
                "release_tag"
            ],
            "release_url": apple_contract.APPLE_V0_1_4_IDENTITY[
                "release_url"
            ],
            "remote_consumer_verified": False,
            "remote_verification": {
                "log_sha256": None,
                "verified_at": None,
                "verifier_commit": None,
            },
            "source_commit": SOURCE_COMMIT,
            "stapled": False,
            "swiftpm_checksum": self.asset_hashes[
                apple_distribution.XCFRAMEWORK_ZIP_NAME
            ],
            "version": apple_contract.APPLE_V0_1_4_IDENTITY[
                "product_version"
            ],
        }
        self.pending = {
            "boundary": apple_contract.APPLE_V0_1_4_BOUNDARY,
            "distribution": copy.deepcopy(self.distribution),
            "identity": copy.deepcopy(apple_contract.APPLE_V0_1_4_IDENTITY),
            "kind": apple_contract.APPLE_PUBLICATION_KIND,
            "schema_version": apple_contract.APPLE_PUBLICATION_SCHEMA_VERSION,
            "source": {
                "canonical_source_tree_sha256": SOURCE_DIGEST,
                "source_parent_commit": SOURCE_COMMIT,
                "tag_commit": TAG_COMMIT,
                "tag_object": TAG_OBJECT,
                "tag_tree": TAG_TREE,
            },
            "status": apple_contract.APPLE_STATUS_PENDING,
        }
        self._write_completion()

        self.receipt_root = self.target / "qperiapt-apple-publication-receipts"
        self.projection_root = (
            self.target / "qperiapt-apple-release-verification" / "projections"
        )
        self.projection_root.mkdir(parents=True, mode=0o700)
        os.chmod(self.projection_root.parent, 0o700)
        os.chmod(self.projection_root, 0o700)
        self.remote_runs_root = (
            self.target / "qperiapt-swift-remote-consumer-runs"
        )
        self.remote_runs_root.mkdir(mode=0o700)
        os.chmod(self.remote_runs_root, 0o700)
        self.results_path = self.artifact / "results.json"
        self.projection_index = 0
        self.remote_run_index = 0

        patches = (
            ("REPOSITORY_ROOT", self.root),
            ("RESULTS_PATH", self.results_path),
            ("APPLE_COMPLETION_ROOT", self.completion_root),
            ("APPLE_PUBLIC_ROOT", self.public_root),
            ("APPLE_PUBLIC_DISTRIBUTION", self.public_distribution),
            ("APPLE_PUBLICATION_RECEIPT_ROOT", self.receipt_root),
            ("APPLE_RELEASE_PROJECTION_ROOT", self.projection_root),
            ("REMOTE_CONSUMER_RUNS_ROOT", self.remote_runs_root),
        )
        for attribute, value in patches:
            patcher = mock.patch.object(publication, attribute, value)
            patcher.start()
        self.addCleanup(patcher.stop)

    def test_runtime_derivation_uses_scanner_visible_guard(self) -> None:
        tree = ast.parse(
            pathlib.Path(publication.__file__).read_text(encoding="utf-8")
        )
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_remote_runtime_from_verifier_snapshot"
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
        self.assertEqual("AppleStablePublicationError", raised.exc.func.id)

    def _write_completion(self) -> None:
        document = {
            "kind": publication.COMPLETION_LEDGER_KIND,
            "public_assets_sha256": dict(self.asset_hashes),
            "release_identity": {
                "product_version": apple_distribution.PRODUCT_VERSION,
                "revision": apple_distribution.RELEASE_REVISION,
                "tag": apple_distribution.RELEASE_TAG,
            },
            "schema_version": publication.COMPLETION_LEDGER_SCHEMA_VERSION,
            "source_commit": SOURCE_COMMIT,
        }
        self.completion.write_bytes(_json_bytes(document))
        os.chmod(self.completion, 0o600)

    def _pending_results(self) -> dict[str, object]:
        manifest = pending_manifest_fixture()
        manifest["proof_source_tree_sha256"] = SOURCE_DIGEST
        manifest["provenance"]["snapshot_commit"] = SOURCE_COMMIT
        manifest["rust_publish"] = rebind_rust_publish_source(
            manifest["rust_publish"],
            source_commit=SOURCE_COMMIT,
            source_digest=SOURCE_DIGEST,
        )
        rebind_stable_current_source(
            manifest,
            source_commit=SOURCE_COMMIT,
            source_digest=SOURCE_DIGEST,
        )
        manifest["release_publications"][
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
        ] = copy.deepcopy(self.pending)
        # The committed results.json is state-selected: the frozen
        # published v0.1.3 cohort is permanent history, and the active
        # v0.1.4 cohort may be absent, pending, or verified (the verified
        # state additionally records the crates.io leaf and activates the
        # v0.1.4 Swift selection). This fixture models the PENDING v0.1.4
        # cohort over the synthetic pre-0.1.3 baseline, so reconstruct
        # that exact projection regardless of which state is installed:
        # drop the crates.io leaf (the pending cohort records none) and
        # rebind the selector to the frozen legacy alpha.2 publication
        # from the contract's own frozen distribution bytes.
        manifest["release_publications"].pop(
            crates_contract.CRATES_IO_PUBLICATION_KEY, None
        )
        swift = manifest["swift_xcframework"]
        swift["active_publication_key"] = (
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        )
        swift["distribution"] = apple_contract.frozen_alpha2_r1_distribution()
        platform = manifest["release_publications"][
            platform_publication_contract.PLATFORM_V0_1_4_PUBLICATION_KEY
        ]
        platform_source = platform["observation"]["source"]
        platform_source.update(
            {
                "canonical_source_tree_sha256": SOURCE_DIGEST,
                "source_parent_commit": SOURCE_COMMIT,
                "tag_commit": TAG_COMMIT,
                "tag_tree": TAG_TREE,
                "verifier_commit": TAG_COMMIT,
            }
        )
        platform["observation"]["candidate_attestation"][
            "source_digest"
        ] = TAG_COMMIT
        release_publication_contract.validate_release_publications(manifest)
        return manifest

    def _write_current_results(self) -> str:
        self.results_path.write_bytes(_json_bytes(self._pending_results()))
        os.chmod(self.results_path, 0o644)
        return hashlib.sha256(self.results_path.read_bytes()).hexdigest()

    def _read_results_fixture(
        self, expected_sha256: str
    ) -> tuple[dict[str, object], str]:
        data = self.results_path.read_bytes()
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            raise publication.AppleStablePublicationError(
                "fixture results hash differs"
            )
        return json.loads(data), actual_sha256

    def _new_remote_run(self) -> pathlib.Path:
        self.remote_run_index += 1
        run = self.remote_runs_root / f"transaction.fixture-{self.remote_run_index}"
        run.mkdir(mode=0o700)
        os.chmod(run, 0o700)
        return run

    def _runtime_remote_inputs(
        self,
        run: pathlib.Path,
    ) -> tuple[pathlib.Path, str]:
        verifier_artifact = run / "verifier-inputs" / "artifact"
        verifier_artifact.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(verifier_artifact.parent, 0o700)
        os.chmod(verifier_artifact, 0o700)
        extracted = (
            run
            / "verifier-inputs"
            / "target"
            / "extracted"
            / "CQPeriapt.xcframework"
        )
        extracted.mkdir(parents=True, mode=0o755)
        verifier_target = run / "verifier-inputs" / "target"
        extraction_root = verifier_target / "extracted"
        os.chmod(verifier_target, 0o700)
        os.chmod(extraction_root, 0o700)
        os.chmod(extracted, 0o755)
        verifier_results = verifier_artifact / "results.json"
        verifier_results.write_bytes(_json_bytes(self._pending_results()))
        os.chmod(verifier_results, 0o600)
        release_assets = run / publication.REMOTE_CONSUMER_RELEASE_ASSETS_NAME
        release_assets.mkdir(mode=0o700, exist_ok=True)
        os.chmod(release_assets, 0o700)
        for name, data in self.asset_bytes.items():
            path = release_assets / name
            path.write_bytes(data)
            os.chmod(path, 0o600)
        log = run / publication.REMOTE_CONSUMER_LOG_NAME
        # Realistic XCTest output: the passing grand-total line is printed once
        # per suite level (test-class, bundle, and outer "All tests"), so it
        # legitimately appears more than once for a clean three-test run.
        log.write_text(
            "/Users/private/RAW_PII_SENTINEL\n"
            "Test Suite 'CQPeriaptTests' passed.\n"
            "\t Executed 3 tests, with 0 failures (0 unexpected) in 0.004 seconds\n"
            "Test Suite 'CQPeriaptPackageTests.xctest' passed.\n"
            "\t Executed 3 tests, with 0 failures (0 unexpected) in 0.004 seconds\n"
            "Test Suite 'All tests' passed.\n"
            "\t Executed 3 tests, with 0 failures (0 unexpected) in 0.004 seconds\n",
            encoding="utf-8",
        )
        os.chmod(log, 0o600)
        return (
            verifier_results,
            hashlib.sha256(verifier_results.read_bytes()).hexdigest(),
        )

    def _collector_projection_parts(
        self,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        release_id = 355_500_000
        expectation = verification.ReleaseExpectation(
            product_version=apple_contract.APPLE_V0_1_4_IDENTITY[
                "product_version"
            ],
            revision=apple_contract.APPLE_V0_1_4_IDENTITY[
                "distribution_revision"
            ],
            tag=apple_contract.APPLE_V0_1_4_IDENTITY["release_tag"],
            source_parent_commit=SOURCE_COMMIT,
            tag_commit=TAG_COMMIT,
            asset_sha256=self.asset_hashes,
            expected_prerelease=False,
        )
        release_view = {
            "assets": [
                {
                    "apiUrl": (
                        f"{verification.API_ASSET_PREFIX}{500_000_000 + index}"
                    ),
                    "contentType": (
                        apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES[name]
                    ),
                    "createdAt": "2026-08-14T09:58:00Z",
                    "digest": f"sha256:{self.asset_hashes[name]}",
                    "downloadCount": index,
                    "id": f"RA_fixture_{index}",
                    "label": "",
                    "name": name,
                    "size": len(self.asset_bytes[name]),
                    "state": "uploaded",
                    "updatedAt": "2026-08-14T09:59:00Z",
                    "url": (
                        f"{verification.RELEASE_DOWNLOAD_PREFIX}"
                        f"{apple_contract.APPLE_V0_1_4_IDENTITY['release_tag']}"
                        f"/{name}"
                    ),
                }
                for index, name in enumerate(
                    apple_contract.APPLE_PUBLIC_ASSET_NAMES,
                    start=1,
                )
            ],
            "databaseId": release_id,
            "isDraft": False,
            "isImmutable": True,
            "isPrerelease": False,
            "publishedAt": "2026-08-14T10:00:00Z",
            "tagName": apple_contract.APPLE_V0_1_4_IDENTITY["release_tag"],
            "targetCommitish": "main",
            "url": apple_contract.APPLE_V0_1_4_IDENTITY["release_url"],
        }
        parsed = verification._parse_release_view(
            _json_bytes(release_view),
            expectation=expectation,
            release_id=release_id,
        )
        return (
            list(parsed.assets),
            verification._expected_subjects(expectation, TAG_OBJECT),
        )

    def _write_projection(self, remote_verified_at: str) -> pathlib.Path:
        self.projection_index += 1
        transaction = (
            self.projection_root
            / f"transaction.fixture-{self.projection_index}"
        )
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        assets, subjects = self._collector_projection_parts()
        publication_record = {
            "draft": False,
            "immutable_release": True,
            "observed_at": "2026-08-14T13:00:00Z",
            "prerelease": False,
            "public_release": True,
            "published_at": "2026-08-14T10:00:00Z",
            "release_attestation": {
                "certificate_san": apple_contract.APPLE_RELEASE_CERTIFICATE_SAN,
                "predicate_type": apple_contract.APPLE_RELEASE_PREDICATE_TYPE,
                "subjects": subjects,
                "verification_record_sha256": "4" * 64,
                "verified": True,
                "verified_at": "2026-08-14T10:01:00Z",
            },
            "release_id": 355_500_000,
            "source": {
                "tag_commit": TAG_COMMIT,
                "tag_object": TAG_OBJECT,
            },
        }
        projection = {
            "assets": assets,
            "kind": publication.APPLE_RELEASE_PROJECTION_KIND,
            "publication": publication_record,
            "release_identity": {
                "repository": publication.APPLE_RELEASE_REPOSITORY,
                "tag": apple_distribution.RELEASE_TAG,
                "url": apple_distribution.RELEASE_URL,
                "visibility": "PUBLIC",
            },
            "schema_version": publication.APPLE_RELEASE_PROJECTION_SCHEMA_VERSION,
            "timestamp_authority": {
                "timestamp": "2026-08-14T10:01:00Z",
                "type": publication.APPLE_RELEASE_TIMESTAMP_AUTHORITY_TYPE,
                "uri": publication.APPLE_RELEASE_TIMESTAMP_AUTHORITY_URI,
            },
        }
        path = transaction / publication.APPLE_RELEASE_PROJECTION_NAME
        path.write_bytes(_json_bytes(projection))
        os.chmod(path, 0o600)
        self.assertLessEqual(remote_verified_at, publication_record["observed_at"])
        return path

    def _emit_remote(self, run: pathlib.Path | None = None) -> pathlib.Path:
        if run is None:
            run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(run)
        codesign = mock.Mock(
            return_value=SimpleNamespace(returncode=0)
        )
        with (
            mock.patch.object(
                publication.apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=copy.deepcopy(self.distribution),
            ) as deep,
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=VERIFIER_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication,
                "require_commit_or_evidence_successor",
                return_value=VERIFIER_COMMIT,
            ),
            mock.patch.object(
                publication,
                "capture_stdout",
                codesign,
            ),
        ):
            path, _digest = publication.emit_remote_consumer_receipt(
                runtime_repository_root=self.root,
                run_directory_name=run.name,
                startup_results_sha256=startup,
                clock=lambda: dt.datetime(2026, 8, 14, 12, 0, tzinfo=dt.UTC),
            )
        self.assertEqual(2, codesign.call_count)
        for call in codesign.call_args_list:
            self.assertEqual(
                ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4"],
                call.args[0][:4],
            )
        call = deep.call_args.kwargs
        for name, argument in (
            (apple_distribution.XCFRAMEWORK_ZIP_NAME, "zip_data"),
            (apple_distribution.APPLE_DISTRIBUTION_NAME, "apple_distribution_data"),
            (apple_distribution.MANIFEST_NAME, "manifest_data"),
            (apple_distribution.SHA256SUMS_NAME, "checksums_data"),
        ):
            self.assertEqual(self.asset_bytes[name], call[argument])
        return path

    def test_cli_derives_outer_runtime_from_fixed_verifier_snapshot(self) -> None:
        run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(run)
        verifier_source = run / "verifier-inputs"
        expected_path = run / publication.REMOTE_CONSUMER_RECEIPT_NAME
        with (
            mock.patch.object(publication, "REPOSITORY_ROOT", verifier_source),
            mock.patch.object(
                publication,
                "emit_remote_consumer_receipt",
                return_value=(expected_path, "a" * 64),
            ) as emitter,
            mock.patch("builtins.print"),
        ):
            status = publication._main(
                ["emit-remote-consumer", run.name, startup]
            )
        self.assertEqual(0, status)
        emitter.assert_called_once_with(
            runtime_repository_root=self.root,
            run_directory_name=run.name,
            startup_results_sha256=startup,
        )

        with (
            mock.patch.object(publication, "REPOSITORY_ROOT", verifier_source),
            mock.patch.object(publication, "emit_remote_consumer_receipt") as emitter,
            mock.patch("builtins.print"),
        ):
            status = publication._main(
                ["emit-remote-consumer", str(self.root), run.name, startup]
            )
            self.assertEqual(2, status)
            emitter.assert_not_called()

    def test_pending_cli_requires_the_pinned_results_digest(self) -> None:
        with (
            mock.patch.object(
                publication,
                "build_pending_receipt",
                return_value=copy.deepcopy(self.pending),
            ) as builder,
            mock.patch.object(
                publication,
                "_publish_receipt",
                return_value=(self.completion, "b" * 64),
            ),
            mock.patch("builtins.print"),
        ):
            status = publication._main(
                ["pending", str(self.completion), "a" * 64]
            )
        self.assertEqual(0, status)
        builder.assert_called_once_with(self.completion, "a" * 64)

        with (
            mock.patch.object(publication, "build_pending_receipt") as builder,
            mock.patch("builtins.print"),
        ):
            status = publication._main(["pending", str(self.completion)])
        self.assertEqual(2, status)
        builder.assert_not_called()

    def test_verifier_snapshot_layout_rejects_alias_and_wrong_bindings(self) -> None:
        run = self._new_remote_run()
        self._runtime_remote_inputs(run)
        verifier_source = run / "verifier-inputs"
        with mock.patch.object(publication, "REPOSITORY_ROOT", verifier_source):
            self.assertEqual(
                (self.root, run.name),
                publication._remote_runtime_from_verifier_snapshot(run.name),
            )
            with self.assertRaises(publication.AppleStablePublicationError):
                publication._remote_runtime_from_verifier_snapshot(
                    "transaction.fixture-other"
                )

        source_alias = run / "verifier-inputs-alias"
        source_alias.symlink_to(verifier_source, target_is_directory=True)
        with mock.patch.object(publication, "REPOSITORY_ROOT", source_alias):
            with self.assertRaisesRegex(
                publication.AppleStablePublicationError,
                "canonical",
            ):
                publication._remote_runtime_from_verifier_snapshot(run.name)

        wrong_runs_root = self.target / "qperiapt-swift-remote-consumer-runs-evil"
        wrong_source = wrong_runs_root / run.name / "verifier-inputs"
        wrong_source.mkdir(parents=True, mode=0o700)
        os.chmod(wrong_runs_root, 0o700)
        os.chmod(wrong_source.parent, 0o700)
        os.chmod(wrong_source, 0o700)
        with mock.patch.object(publication, "REPOSITORY_ROOT", wrong_source):
            with self.assertRaisesRegex(
                publication.AppleStablePublicationError,
                "runs-root binding",
            ):
                publication._remote_runtime_from_verifier_snapshot(run.name)

    def test_completed_clean_tagged_distribution_builds_pending_leaf(self) -> None:
        with (
            mock.patch.object(
                publication,
                "_read_results_snapshot",
                return_value=(self._pending_results(), "a" * 64),
            ),
            mock.patch.object(
                publication,
                "_validate_clean_annotated_tag",
                return_value=copy.deepcopy(self.pending["source"]),
            ) as tagged_source,
            mock.patch.object(
                publication.apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=copy.deepcopy(self.distribution),
            ) as deep,
        ):
            receipt = publication.build_pending_receipt(
                self.completion, "a" * 64
            )

        self.assertEqual(self.pending, receipt)
        apple_contract.validate_apple_publications(
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_4_PUBLICATION_KEY: receipt
                }
            }
        )
        self.assertEqual(SOURCE_COMMIT, deep.call_args.kwargs["expected_source_commit"])
        tagged_source.assert_called_once_with(SOURCE_COMMIT, SOURCE_DIGEST)

    def test_tag_source_identity_binds_results_only_child_and_tree(self) -> None:
        def git_result(_root: pathlib.Path, arguments: list[str]) -> str:
            if arguments[:2] == ["cat-file", "-t"]:
                return "tag"
            revision = arguments[-1]
            if revision.endswith("^{commit}"):
                return TAG_COMMIT
            if revision.endswith("^{tree}"):
                return TAG_TREE
            return TAG_OBJECT

        with (
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=TAG_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication, "run_git_text", side_effect=git_result
            ),
            mock.patch.object(
                publication, "require_direct_results_only_child"
            ) as direct_child,
            mock.patch.object(
                publication,
                "repository_paths",
                return_value=["artifact/results.json"],
            ),
            mock.patch.object(
                publication,
                "canonical_tree_digest",
                return_value=SOURCE_DIGEST,
            ),
        ):
            source = publication._validate_clean_annotated_tag(
                SOURCE_COMMIT, SOURCE_DIGEST
            )

        self.assertEqual(self.pending["source"], source)
        direct_child.assert_called_once_with(
            self.root, SOURCE_COMMIT, TAG_COMMIT
        )

    def test_pending_rejects_hash_source_tag_cleanliness_and_incomplete_cleanup(
        self,
    ) -> None:
        cases = ("hash", "source", "tag", "dirty", "leftover")
        for case in cases:
            with self.subTest(case=case):
                self._write_completion()
                leftover = self.completion_transaction / "source"
                if case == "hash":
                    document = json.loads(self.completion.read_text(encoding="ascii"))
                    document["public_assets_sha256"][
                        apple_distribution.MANIFEST_NAME
                    ] = "f" * 64
                    self.completion.write_bytes(_json_bytes(document))
                elif case == "source":
                    document = json.loads(self.completion.read_text(encoding="ascii"))
                    document["source_commit"] = "9" * 40
                    self.completion.write_bytes(_json_bytes(document))
                elif case == "leftover":
                    leftover.mkdir()
                os.chmod(self.completion, 0o600)
                tag_error = (
                    publication.AppleStablePublicationError(
                        f"fixture {case} source/tag rejection"
                    )
                    if case in {"tag", "dirty"}
                    else None
                )

                with (
                    mock.patch.object(
                        publication,
                        "_read_results_snapshot",
                        return_value=(self._pending_results(), "a" * 64),
                    ),
                    mock.patch.object(
                        publication,
                        "_validate_clean_annotated_tag",
                        return_value=copy.deepcopy(self.pending["source"]),
                        side_effect=tag_error,
                    ),
                    mock.patch.object(
                        publication.apple_distribution,
                        "project_trusted_results_candidate_distribution",
                        return_value=copy.deepcopy(self.distribution),
                    ),
                ):
                    with self.assertRaises(publication.AppleStablePublicationError):
                        publication.build_pending_receipt(
                            self.completion, "a" * 64
                        )
                if leftover.exists():
                    leftover.rmdir()

    def test_remote_receipt_derives_fixed_bytes_results_log_and_clean_head(
        self,
    ) -> None:
        path = self._emit_remote()
        receipt = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(publication.REMOTE_CONSUMER_BOUNDARY, receipt["boundary"])
        self.assertNotIn("cleanup_verified", receipt["verification"])
        self.assertTrue(receipt["verification"]["codesign_verified"])
        self.assertEqual(self.asset_hashes, receipt["assets_sha256"])
        self.assertEqual(SOURCE_COMMIT, receipt["source_commit"])
        self.assertEqual(VERIFIER_COMMIT, receipt["verifier_commit"])
        self.assertEqual("2026-08-14T12:00:00Z", receipt["verified_at"])
        self.assertEqual(
            hashlib.sha256(
                (
                    path.parent / publication.REMOTE_CONSUMER_LOG_NAME
                ).read_bytes()
            ).hexdigest(),
            receipt["log_sha256"],
        )
        text = path.read_text(encoding="ascii")
        marker = publication._remote_success_marker(
            path,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            self.root,
        )
        self.assertNotIn("RAW_PII_SENTINEL", text)
        self.assertNotIn("/Users/", text)
        self.assertNotIn("RAW_PII_SENTINEL", marker)
        self.assertNotIn("/Users/", marker)
        self.assertIn(
            "path=target/qperiapt-swift-remote-consumer-runs/transaction.",
            marker,
        )
        self.assertNotIn("path", json.dumps(receipt).lower())
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(1, path.stat().st_nlink)

    def test_run_parent_sync_and_codesign_precede_receipt_commit(self) -> None:
        run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(run)
        events: list[str] = []
        real_open = publication.open_private_direct_child_handle
        real_sync = publication.sync_private_directory_parent
        real_commit = (
            receipt_io.PreparedPrivateJsonPublication.commit_after_revalidation
        )

        def pin_run(**kwargs: object):
            events.append("pin-run")
            self.assertIs(True, kwargs["sync_safe_root_parent"])
            return real_open(**kwargs)

        def sync_parent(*args: object, **kwargs: object) -> None:
            events.append("sync-parent")
            real_sync(*args, **kwargs)

        def codesign(*_args: object, **_kwargs: object):
            events.append("codesign")
            return SimpleNamespace(returncode=0)

        def write_receipt(
            prepared: receipt_io.PreparedPrivateJsonPublication,
        ) -> str:
            events.append("write-receipt")
            return real_commit(prepared)

        with (
            mock.patch.object(
                publication.apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=copy.deepcopy(self.distribution),
            ),
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=VERIFIER_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication,
                "require_commit_or_evidence_successor",
                return_value=VERIFIER_COMMIT,
            ),
            mock.patch.object(
                publication,
                "open_private_direct_child_handle",
                side_effect=pin_run,
            ),
            mock.patch.object(
                publication,
                "sync_private_directory_parent",
                side_effect=sync_parent,
            ),
            mock.patch.object(
                receipt_io.PreparedPrivateJsonPublication,
                "commit_after_revalidation",
                autospec=True,
                side_effect=write_receipt,
            ),
            mock.patch.object(
                publication,
                "capture_stdout",
                side_effect=codesign,
            ),
        ):
            path, _digest = publication.emit_remote_consumer_receipt(
                runtime_repository_root=self.root,
                run_directory_name=run.name,
                startup_results_sha256=startup,
            )
        self.assertEqual(
            [
                "pin-run",
                "sync-parent",
                "codesign",
                "pin-run",
                "sync-parent",
                "codesign",
                "write-receipt",
            ],
            events,
        )
        self.assertTrue(path.is_file())

        for label, open_effect, sync_effect, codesign_result in (
            (
                "target-parent-sync",
                publication.PublicationReceiptIOError(
                    "injected target parent sync failure"
                ),
                None,
                SimpleNamespace(returncode=0),
            ),
            (
                "runs-root-sync",
                None,
                publication.PublicationReceiptIOError(
                    "injected runs-root parent sync failure"
                ),
                SimpleNamespace(returncode=0),
            ),
            ("codesign", None, None, SimpleNamespace(returncode=1)),
        ):
            with self.subTest(label=label):
                failed_run = self._new_remote_run()
                _results, failed_startup = self._runtime_remote_inputs(
                    failed_run
                )
                open_patch = (
                    mock.Mock(side_effect=open_effect)
                    if open_effect is not None
                    else mock.Mock(side_effect=real_open)
                )
                sync_patch = (
                    mock.Mock(side_effect=sync_effect)
                    if sync_effect is not None
                    else mock.Mock(side_effect=real_sync)
                )
                with (
                    mock.patch.object(
                        publication.apple_distribution,
                        "project_trusted_results_candidate_distribution",
                        return_value=copy.deepcopy(self.distribution),
                    ),
                    mock.patch.object(
                        publication,
                        "inspect_worktree",
                        return_value=SimpleNamespace(
                            commit=VERIFIER_COMMIT,
                            dirty=False,
                        ),
                    ),
                    mock.patch.object(
                        publication,
                        "require_commit_or_evidence_successor",
                        return_value=VERIFIER_COMMIT,
                    ),
                    mock.patch.object(
                        publication,
                        "open_private_direct_child_handle",
                        open_patch,
                    ),
                    mock.patch.object(
                        publication,
                        "sync_private_directory_parent",
                        sync_patch,
                    ),
                    mock.patch.object(
                        publication,
                        "capture_stdout",
                        return_value=codesign_result,
                    ),
                ):
                    with self.assertRaises(
                        (
                            publication.PublicationReceiptIOError,
                            publication.AppleStablePublicationError,
                        )
                    ):
                        publication.emit_remote_consumer_receipt(
                            runtime_repository_root=self.root,
                            run_directory_name=failed_run.name,
                            startup_results_sha256=failed_startup,
                        )
                self.assertFalse(
                    (
                        failed_run
                        / publication.REMOTE_CONSUMER_RECEIPT_NAME
                    ).exists()
                )

    def test_pinned_remote_run_swap_during_codesign_fails_closed(self) -> None:
        run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(run)
        moved = self.remote_runs_root / f"{run.name}.moved"

        def codesign_and_swap(*_args: object, **_kwargs: object):
            run.rename(moved)
            run.mkdir(mode=0o700)
            os.chmod(run, 0o700)
            return SimpleNamespace(returncode=0)

        with (
            mock.patch.object(
                publication.apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=copy.deepcopy(self.distribution),
            ),
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=VERIFIER_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication,
                "require_commit_or_evidence_successor",
                return_value=VERIFIER_COMMIT,
            ),
            mock.patch.object(
                publication,
                "capture_stdout",
                side_effect=codesign_and_swap,
            ),
            self.assertRaisesRegex(
                publication.AppleStablePublicationError,
                "identity changed while pinned",
            ),
        ):
            publication.emit_remote_consumer_receipt(
                runtime_repository_root=self.root,
                run_directory_name=run.name,
                startup_results_sha256=startup,
            )
        self.assertFalse(
            (moved / publication.REMOTE_CONSUMER_RECEIPT_NAME).exists()
        )

    def test_target_swap_in_commit_window_leaves_receipt_bytes_unchanged(
        self,
    ) -> None:
        run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(run)
        target = run / "verifier-inputs" / "target"
        moved = run / "verifier-inputs" / "target-moved"
        before = {
            path.relative_to(self.remote_runs_root): path.read_bytes()
            for path in self.remote_runs_root.rglob(
                publication.REMOTE_CONSUMER_RECEIPT_NAME
            )
        }
        calls = 0

        def codesign_and_swap_second_phase(
            *_args: object,
            **_kwargs: object,
        ) -> SimpleNamespace:
            nonlocal calls
            calls += 1
            if calls == 2:
                target.rename(moved)
                target.mkdir(mode=0o700)
                os.chmod(target, 0o700)
            return SimpleNamespace(returncode=0)

        with (
            mock.patch.object(
                publication.apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=copy.deepcopy(self.distribution),
            ),
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=VERIFIER_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication,
                "require_commit_or_evidence_successor",
                return_value=VERIFIER_COMMIT,
            ),
            mock.patch.object(
                publication,
                "capture_stdout",
                side_effect=codesign_and_swap_second_phase,
            ),
            self.assertRaisesRegex(
                publication.AppleStablePublicationError,
                "identity changed while pinned",
            ),
        ):
            publication.emit_remote_consumer_receipt(
                runtime_repository_root=self.root,
                run_directory_name=run.name,
                startup_results_sha256=startup,
            )
        self.assertEqual(2, calls)
        after = {
            path.relative_to(self.remote_runs_root): path.read_bytes()
            for path in self.remote_runs_root.rglob(
                publication.REMOTE_CONSUMER_RECEIPT_NAME
            )
        }
        self.assertEqual(before, after)
        self.assertEqual([], list(run.glob(".apple-remote-consumer-receipt.json.pending-*")))

    def test_postrename_run_swap_preserves_structured_committed_error(self) -> None:
        run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(run)
        moved = self.remote_runs_root / f"{run.name}.committed-moved"
        real_rename = receipt_io._rename_noreplace

        def rename_and_swap(
            directory_fd: int,
            source_leaf: str,
            destination_leaf: str,
        ) -> None:
            real_rename(directory_fd, source_leaf, destination_leaf)
            if destination_leaf == publication.REMOTE_CONSUMER_RECEIPT_NAME:
                run.rename(moved)
                run.mkdir(mode=0o700)
                os.chmod(run, 0o700)

        with (
            mock.patch.object(
                publication.apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=copy.deepcopy(self.distribution),
            ),
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=VERIFIER_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication,
                "require_commit_or_evidence_successor",
                return_value=VERIFIER_COMMIT,
            ),
            mock.patch.object(
                publication,
                "capture_stdout",
                return_value=SimpleNamespace(returncode=0),
            ),
            mock.patch.object(
                receipt_io,
                "_rename_noreplace",
                side_effect=rename_and_swap,
            ),
            self.assertRaises(
                publication.PublicationReceiptCommittedError
            ) as caught,
        ):
            publication.emit_remote_consumer_receipt(
                runtime_repository_root=self.root,
                run_directory_name=run.name,
                startup_results_sha256=startup,
            )
        self.assertEqual(
            publication.REMOTE_CONSUMER_RECEIPT_NAME,
            caught.exception.leaf,
        )
        self.assertEqual(64, len(caught.exception.digest or ""))
        self.assertFalse(
            (run / publication.REMOTE_CONSUMER_RECEIPT_NAME).exists()
        )
        self.assertTrue(
            (moved / publication.REMOTE_CONSUMER_RECEIPT_NAME).is_file()
        )

    def test_cli_visibility_error_markers_are_machine_parseable(self) -> None:
        for visibility in ("committed", "indeterminate"):
            with self.subTest(visibility=visibility):
                error = publication.PublicationReceiptCommittedError(
                    "fixture visibility failure",
                    leaf=publication.REMOTE_CONSUMER_RECEIPT_NAME,
                    digest="a" * 64,
                    visibility=visibility,
                )
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(publication, "_main", side_effect=error),
                    mock.patch.object(publication.sys, "argv", ["fixture"]),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(125, publication.main())
                self.assertEqual(
                    "PUBLICATION_RECEIPT_COMMITTED_ERROR "
                    f"visibility={visibility} "
                    f"leaf={publication.REMOTE_CONSUMER_RECEIPT_NAME} "
                    f"sha256={'a' * 64}\n",
                    stdout.getvalue(),
                )
                self.assertNotIn("PASS", stdout.getvalue())
                self.assertEqual("", stderr.getvalue())

    def test_remote_receipt_rejects_asset_log_results_checkout_and_no_replace(
        self,
    ) -> None:
        successful = self._emit_remote()
        successful_bytes = successful.read_bytes()
        for case in ("asset", "warning", "startup", "end-results", "dirty"):
            with self.subTest(case=case):
                run = self._new_remote_run()
                verifier_results, startup = self._runtime_remote_inputs(run)
                if case == "asset":
                    asset = (
                        run
                        / publication.REMOTE_CONSUMER_RELEASE_ASSETS_NAME
                        / apple_distribution.MANIFEST_NAME
                    )
                    asset.write_bytes(b"changed bytes\n")
                    os.chmod(asset, 0o600)
                if case == "warning":
                    log = run / publication.REMOTE_CONSUMER_LOG_NAME
                    log.write_text(
                        "warning: injected\nExecuted 3 tests, with 0 failures\n",
                        encoding="utf-8",
                    )
                    os.chmod(log, 0o600)
                if case == "startup":
                    startup = "f" * 64

                real_snapshot = publication._private_runtime_snapshot_at

                def snapshot_then_mutate(*args: object, **kwargs: object):
                    result = real_snapshot(*args, **kwargs)
                    if (
                        case == "end-results"
                        and kwargs.get("label") == "remote consumer test log"
                    ):
                        verifier_results.write_bytes(b'{"changed":true}\n')
                        os.chmod(verifier_results, 0o600)
                    return result

                with (
                    mock.patch.object(
                        publication.apple_distribution,
                        "project_trusted_results_candidate_distribution",
                        return_value=copy.deepcopy(self.distribution),
                    ),
                    mock.patch.object(
                        publication,
                        "inspect_worktree",
                        return_value=SimpleNamespace(
                            commit=VERIFIER_COMMIT,
                            dirty=case == "dirty",
                        ),
                    ),
                    mock.patch.object(
                        publication,
                        "require_commit_or_evidence_successor",
                        return_value=VERIFIER_COMMIT,
                    ),
                    mock.patch.object(
                        publication,
                        "_private_runtime_snapshot_at",
                        side_effect=snapshot_then_mutate,
                    ),
                    mock.patch.object(
                        publication,
                        "capture_stdout",
                        return_value=SimpleNamespace(returncode=0),
                    ),
                ):
                    with self.assertRaises(publication.AppleStablePublicationError):
                        publication.emit_remote_consumer_receipt(
                            runtime_repository_root=self.root,
                            run_directory_name=run.name,
                            startup_results_sha256=startup,
                        )
                self.assertFalse(
                    (run / publication.REMOTE_CONSUMER_RECEIPT_NAME).exists()
                )
                self.assertEqual(successful_bytes, successful.read_bytes())

        competing_run = self._new_remote_run()
        _results, startup = self._runtime_remote_inputs(competing_run)
        competing = (
            competing_run / publication.REMOTE_CONSUMER_RECEIPT_NAME
        )
        competing.write_bytes(b"competing complete receipt\n")
        os.chmod(competing, 0o600)
        original = competing.read_bytes()
        with self.assertRaises(publication.AppleStablePublicationError):
            with (
                mock.patch.object(
                    publication.apple_distribution,
                    "project_trusted_results_candidate_distribution",
                    return_value=copy.deepcopy(self.distribution),
                ),
                mock.patch.object(
                    publication,
                    "inspect_worktree",
                    return_value=SimpleNamespace(
                        commit=VERIFIER_COMMIT,
                        dirty=False,
                    ),
                ),
                mock.patch.object(
                    publication,
                    "require_commit_or_evidence_successor",
                    return_value=VERIFIER_COMMIT,
                ),
                mock.patch.object(
                    publication,
                    "capture_stdout",
                    return_value=SimpleNamespace(returncode=0),
                ),
            ):
                publication.emit_remote_consumer_receipt(
                    runtime_repository_root=self.root,
                    run_directory_name=competing_run.name,
                    startup_results_sha256=startup,
                )
        self.assertEqual(original, competing.read_bytes())

        second_success = self._emit_remote()
        self.assertNotEqual(successful.parent, second_success.parent)
        self.assertEqual(successful_bytes, successful.read_bytes())

    def test_collector_projection_promotes_with_exact_remote_receipt(
        self,
    ) -> None:
        results_sha256 = self._write_current_results()
        remote_path = self._emit_remote()
        projection_path = self._write_projection("2026-08-14T12:00:00Z")
        with (
            mock.patch.object(
                publication,
                "_read_results_snapshot",
                side_effect=self._read_results_fixture,
            ),
            mock.patch.object(
                publication,
                "inspect_worktree",
                return_value=SimpleNamespace(commit=VERIFIER_COMMIT, dirty=False),
            ),
            mock.patch.object(
                publication,
                "require_commit_or_evidence_successor",
                return_value=VERIFIER_COMMIT,
            ),
        ):
            verified = publication.promote_receipt(
                results_sha256,
                projection_path,
                remote_path,
            )
        self.assertEqual(apple_contract.APPLE_STATUS_VERIFIED, verified["status"])
        self.assertEqual(
            self.pending["distribution"]["artifact_sha256"],
            verified["distribution"]["artifact_sha256"],
        )
        self.assertTrue(verified["distribution"]["remote_consumer_verified"])
        apple_contract.validate_apple_publication_transition(
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_4_PUBLICATION_KEY: self.pending
                }
            },
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_4_PUBLICATION_KEY: verified
                }
            },
        )

    def test_promotion_rejects_wrong_asset_source_and_timestamps(self) -> None:
        for case in (
            "asset",
            "asset-order-swap",
            "source",
            "timestamp",
            "boundary",
        ):
            with self.subTest(case=case):
                results_sha256 = self._write_current_results()
                remote_path = self._emit_remote()
                projection_path = self._write_projection("2026-08-14T12:00:00Z")
                if case == "asset":
                    projection = json.loads(
                        projection_path.read_text(encoding="ascii")
                    )
                    projection["assets"][0]["sha256"] = "f" * 64
                    projection_path.write_bytes(_json_bytes(projection))
                    os.chmod(projection_path, 0o600)
                elif case == "asset-order-swap":
                    projection = json.loads(
                        projection_path.read_text(encoding="ascii")
                    )
                    projection["assets"][0], projection["assets"][1] = (
                        projection["assets"][1],
                        projection["assets"][0],
                    )
                    projection_path.write_bytes(_json_bytes(projection))
                    os.chmod(projection_path, 0o600)
                elif case == "source":
                    remote = json.loads(remote_path.read_text(encoding="ascii"))
                    remote["source_commit"] = "9" * 40
                    remote_path.write_bytes(_json_bytes(remote))
                    os.chmod(remote_path, 0o600)
                elif case == "timestamp":
                    projection = json.loads(
                        projection_path.read_text(encoding="ascii")
                    )
                    projection["publication"]["observed_at"] = (
                        "2026-08-14T11:59:59Z"
                    )
                    projection_path.write_bytes(_json_bytes(projection))
                    os.chmod(projection_path, 0o600)
                else:
                    remote = json.loads(remote_path.read_text(encoding="ascii"))
                    remote["boundary"] = "forged cleanup-inclusive boundary"
                    remote_path.write_bytes(_json_bytes(remote))
                    os.chmod(remote_path, 0o600)
                expected_failure = (
                    self.assertRaisesRegex(
                        publication.AppleStablePublicationError,
                        "Apple GitHub release asset binding differs for "
                        "APPLE_DISTRIBUTION.json",
                    )
                    if case == "asset-order-swap"
                    else self.assertRaises(
                        publication.AppleStablePublicationError
                    )
                )
                with (
                    mock.patch.object(
                        publication,
                        "_read_results_snapshot",
                        side_effect=self._read_results_fixture,
                    ),
                    mock.patch.object(
                        publication,
                        "inspect_worktree",
                        return_value=SimpleNamespace(
                            commit=VERIFIER_COMMIT,
                            dirty=False,
                        ),
                    ),
                    mock.patch.object(
                        publication,
                        "require_commit_or_evidence_successor",
                        return_value=VERIFIER_COMMIT,
                    ),
                    expected_failure,
                ):
                    publication.promote_receipt(
                        results_sha256,
                        projection_path,
                        remote_path,
                    )


if __name__ == "__main__":
    unittest.main()
