#!/usr/bin/env python3
"""Focused transaction and mutation tests for stable publication collection."""

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
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from unittest import mock

from bounded_process import BoundedProcessError, BoundedResult, capture_stdout
import platform_stable_publication as publication
import platform_stable_publication_contract as contract
import platform_candidate_attestation as candidate_attestation
import platform_distribution
import platform_distribution_contract as distribution_contract
import publication_receipt_io as receipt_io


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    ).encode("ascii")


class QueueClock:
    def __init__(self, *values: str) -> None:
        self.values = [
            dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=dt.UTC
            )
            for value in values
        ]

    def __call__(self) -> dt.datetime:
        if not self.values:
            raise AssertionError("fixture clock was called too many times")
        return self.values.pop(0)


class RemoteFixtureRunner:
    def __init__(
        self,
        *,
        repository_view: dict[str, object],
        release_before: dict[str, object],
        release_after: dict[str, object],
        verification: dict[str, object],
    ) -> None:
        self.repository_view = repository_view
        self.release_before = release_before
        self.release_after = release_after
        self.verification = verification
        self.calls: list[tuple[str, ...]] = []
        self.release_views = 0

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        maximum_bytes: int,
        stderr: int,
        environment: Mapping[str, str],
    ) -> BoundedResult:
        del timeout_seconds, stderr, environment
        command = tuple(argv)
        self.calls.append(command)
        if command[1:3] == ("repo", "view"):
            value = self.repository_view
        elif command[1:3] == ("release", "view"):
            value = (
                self.release_before
                if self.release_views == 0
                else self.release_after
            )
            self.release_views += 1
        elif command[1:3] == ("release", "verify"):
            value = self.verification
        else:
            raise AssertionError(f"unexpected fixture command: {command!r}")
        payload = json.dumps(value, sort_keys=True).encode("ascii") + b"\n"
        if len(payload) > maximum_bytes:
            raise AssertionError("fixture output exceeds requested bound")
        return BoundedResult(0, payload)


class AssetSinkRunner:
    def __init__(
        self,
        assets: Mapping[str, bytes],
        *,
        mutate: Callable[[str, bytes], bytes] | None = None,
    ) -> None:
        self.assets = dict(assets)
        self.mutate = mutate
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        output_directory_fd: int,
        output_name: str,
        timeout_seconds: int,
        maximum_bytes: int,
        stderr: int,
        environment: Mapping[str, str],
    ) -> BoundedResult:
        del timeout_seconds, stderr, environment
        command = tuple(argv)
        self.calls.append(command)
        pattern_index = command.index("--pattern")
        name = command[pattern_index + 1]
        data = self.assets[name]
        if self.mutate is not None:
            data = self.mutate(name, data)
        if len(data) > maximum_bytes:
            raise BoundedProcessError("output_limit", "fixture exceeded bound")
        descriptor = os.open(
            output_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=output_directory_fd,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return BoundedResult(0)


class PlatformV013PublicationTests(unittest.TestCase):
    TAG_COMMIT = "1" * 40
    SOURCE_PARENT_COMMIT = "4" * 40
    TAG_OBJECT = "2" * 40
    TAG_TREE = "3" * 40
    SOURCE_DIGEST = "4" * 64
    RELEASE_ID = 2_468_013

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.candidate_root = self.root / "candidate-projections"
        self.assembly_root = self.root / "release-candidates"
        self.receipt_root = self.root / "publication-receipts"
        self.verification_root = self.root / "publication-verification"
        self.raw_root = self.verification_root / "raw"
        self.download_root = self.verification_root / "downloads"
        self.worktree_root = self.root / "publication-worktrees"
        for path in (
            self.candidate_root,
            self.assembly_root,
            self.receipt_root,
            self.raw_root,
            self.download_root,
            self.worktree_root,
        ):
            path.mkdir(parents=True, mode=0o700)
            os.chmod(path, 0o700)
        os.chmod(self.verification_root, 0o700)
        self.verifier = self.worktree_root / "M"
        self.verifier.mkdir(mode=0o700)
        os.chmod(self.verifier, 0o700)
        (self.verifier / ".git").mkdir(mode=0o700)

        replacements = (
            (publication, "PLATFORM_PUBLICATION_RECEIPT_ROOT", self.receipt_root),
            (
                publication,
                "PLATFORM_PUBLICATION_VERIFICATION_ROOT",
                self.verification_root,
            ),
            (publication, "PLATFORM_PUBLICATION_RAW_ROOT", self.raw_root),
            (
                publication,
                "PLATFORM_PUBLICATION_DOWNLOAD_ROOT",
                self.download_root,
            ),
            (
                publication,
                "PLATFORM_PUBLICATION_WORKTREE_ROOT",
                self.worktree_root,
            ),
            (
                candidate_attestation,
                "CANDIDATE_PROJECTION_ROOT",
                self.candidate_root,
            ),
            (
                platform_distribution,
                "PLATFORM_RELEASE_CANDIDATE_ROOT",
                self.assembly_root,
            ),
        )
        for module, attribute, value in replacements:
            patcher = mock.patch.object(module, attribute, value)
            patcher.start()
        self.addCleanup(patcher.stop)
        self.source = publication.SourceObservation(
            canonical_source_tree_sha256=self.SOURCE_DIGEST,
            source_parent_commit=self.SOURCE_PARENT_COMMIT,
            source_date_epoch=1_700_000_000,
            tag_commit=self.TAG_COMMIT,
            tag_object=self.TAG_OBJECT,
            tag_tree=self.TAG_TREE,
            verifier_commit=self.TAG_COMMIT,
        )
        self.tools = publication.AndroidVerificationTools(
            llvm_nm=self._tool("llvm-nm", b"llvm-nm fixture\n"),
            llvm_readelf=self._tool("llvm-readelf", b"llvm-readelf fixture\n"),
            apksigner=self._tool("apksigner", b"apksigner fixture\n"),
            zipalign=self._tool("zipalign", b"zipalign fixture\n"),
        )
        self.github_cli = publication.github_release.GitHubCliIdentity(
            path="/fixture/gh",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o755,
            uid=os.geteuid(),
            link_count=1,
            size=10,
            sha256="a" * 64,
        )
        self.select_github_cli = mock.Mock(return_value=self.github_cli)
        self.resample_github_cli = mock.Mock(return_value=None)
        for attribute, replacement in (
            ("select_github_cli", self.select_github_cli),
            ("resample_github_cli", self.resample_github_cli),
        ):
            patcher = mock.patch.object(
                publication.github_release,
                attribute,
                replacement,
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_direct_child_sanitizer_uses_scanner_visible_guard(self) -> None:
        tree = ast.parse(
            pathlib.Path(publication.__file__).read_text(encoding="utf-8")
        )
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_normalize_direct_child"
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
        self.assertEqual("PlatformV013PublicationError", raised.exc.func.id)

    def _tool(self, name: str, data: bytes) -> pathlib.Path:
        directory = self.root / "tools"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / name
        path.write_bytes(data)
        os.chmod(path, 0o700)
        return path

    def _private_parent(self, root: pathlib.Path, name: str) -> pathlib.Path:
        parent = root / name
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o700)
        return parent

    def _candidate_projection(self, name: str = "candidate") -> pathlib.Path:
        parent = self._private_parent(self.candidate_root, name)
        path = parent / candidate_attestation.PROJECTION_NAME
        value = self._candidate_projection_value()
        path.write_bytes(_canonical_json(value))
        os.chmod(path, 0o600)
        return path

    def _candidate_projection_value(
        self, asset_digests: Mapping[str, str] | None = None
    ) -> dict[str, object]:
        digests = dict(asset_digests or {})
        for index, name in enumerate(contract.CANDIDATE_SUBJECT_NAMES, start=1):
            digests.setdefault(name, f"{index:064x}")
        return {
            "certificate_san": contract.CANDIDATE_SIGNER_WORKFLOW,
            "predicate_type": contract.CANDIDATE_PREDICATE_TYPE,
            "security_gate": self._security_gate_projection(
                digests[distribution_contract.SOURCE_SECURITY_GATE]
            ),
            "signer_workflow": contract.CANDIDATE_SIGNER_WORKFLOW,
            "source_digest": self.TAG_COMMIT,
            "source_ref": contract.RELEASE_REF,
            "subjects": [
                {"digest": {"sha256": digests[name]}, "name": name}
                for name in contract.CANDIDATE_SUBJECT_NAMES
            ],
            "verification_record_sha256": "5" * 64,
            "verified": True,
            "verified_at": "2026-08-14T01:00:00Z",
            "workflow_run_attempt": 2,
            "workflow_run_id": 31_700_000_001,
        }

    def _security_gate_projection(
        self, receipt_sha256: str
    ) -> dict[str, object]:
        def workflow(
            *,
            name: str,
            path: str,
            run_id: int,
            jobs: list[dict[str, object]],
            digest: str,
        ) -> dict[str, object]:
            return {
                "conclusion": "success",
                "event": "push",
                "head_branch": "main",
                "head_sha": self.TAG_COMMIT,
                "jobs": jobs,
                "run_attempt": 1,
                "run_id": run_id,
                "status": "completed",
                "workflow_name": name,
                "workflow_path": path,
                "workflow_sha256": digest,
            }

        constant_time_jobs = [
            {
                "architecture": architecture,
                "conclusion": "success",
                "implementation": implementation,
                "job_id": 100 + index,
                "name": name,
                "status": "completed",
            }
            for index, (architecture, implementation, name) in enumerate(
                distribution_contract.CONSTANT_TIME_JOB_CONTRACT
            )
        ]
        codeql_jobs = [
            {
                "conclusion": "success",
                "job_id": 200 + index,
                "language": language,
                "name": name,
                "status": "completed",
            }
            for index, (language, name) in enumerate(
                distribution_contract.CODEQL_JOB_CONTRACT
            )
        ]
        code_scanning_analyses = [
            {
                "analysis_id": 300 + index,
                "analysis_key": distribution_contract.CODEQL_ANALYSIS_KEY,
                "category": category,
                "commit_sha": self.TAG_COMMIT,
                "error": "",
                "ref": distribution_contract.MAIN_REF,
                "results_count": 0,
                "rules_count": 20 + index,
                "tool": {
                    "name": "CodeQL",
                    "version": distribution_contract.CODEQL_TOOL_VERSION,
                },
                "warning": "",
            }
            for index, (_language, category) in enumerate(
                distribution_contract.CODEQL_ANALYSIS_CONTRACT
            )
        ]
        return {
            "code_scanning": {
                "analyses": code_scanning_analyses,
                "main_ref": {
                    "commit_sha": self.TAG_COMMIT,
                    "ref": distribution_contract.MAIN_REF,
                },
                "open_alerts": [],
            },
            "kind": distribution_contract.SOURCE_SECURITY_GATE_KIND,
            "observation_tools": {
                "github_cli": {
                    "name": "gh",
                    "path": "/usr/bin/gh",
                    "sha256": "c" * 64,
                    "version": "gh version 2.94.0 (2026-08-01)",
                }
            },
            "receipt_sha256": receipt_sha256,
            "repository": distribution_contract.REPOSITORY,
            "schema_version": (
                distribution_contract.SOURCE_SECURITY_GATE_SCHEMA_VERSION
            ),
            "source_parent_commit": self.SOURCE_PARENT_COMMIT,
            "tag_commit": self.TAG_COMMIT,
            "workflows": {
                "ci": workflow(
                    name=distribution_contract.CI_WORKFLOW_NAME,
                    path=distribution_contract.CI_WORKFLOW_PATH,
                    run_id=10,
                    jobs=constant_time_jobs,
                    digest="a" * 64,
                ),
                "codeql": workflow(
                    name=distribution_contract.CODEQL_WORKFLOW_NAME,
                    path=distribution_contract.CODEQL_WORKFLOW_PATH,
                    run_id=20,
                    jobs=codeql_jobs,
                    digest="b" * 64,
                ),
            },
        }

    def _source_inspector(
        self, *_args: object, **_kwargs: object
    ) -> publication.SourceObservation:
        return self.source

    def _pending_receipt(
        self,
        name: str,
        *,
        candidate_path: pathlib.Path | None = None,
        assets: Mapping[str, bytes] | None = None,
        manifest: Mapping[str, object] | None = None,
        assembly_receipt: pathlib.Path | None = None,
    ) -> pathlib.Path:
        if assets is None or manifest is None:
            generated_assets, generated_manifest = self._asset_fixture()
            assets = generated_assets
            manifest = generated_manifest
        if candidate_path is None:
            candidate_path = self._candidate_for_assets(
                f"candidate-{name}", assets
            )
        if assembly_receipt is None:
            assembly_receipt = self._assembly_receipt(
                f"transaction.{name}",
                assets,
                manifest,
            )
        output, digest, source = publication.assemble_pending_receipt(
            candidate_path,
            assembly_receipt,
            self.verifier,
            runner=lambda *_args, **_kwargs: BoundedResult(0),
            clock=QueueClock("2026-08-14T02:00:00Z"),
            source_environment={},
            git_tool="/usr/bin/git",
            source_inspector=self._source_inspector,
        )
        self.assertEqual(self.source, source)
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), digest)
        return output

    def _asset_fixture(self) -> tuple[dict[str, bytes], dict[str, object]]:
        assets = {
            name: f"fresh public bytes for {name}\n".encode("ascii")
            for name in contract.PUBLIC_ASSET_NAMES
        }
        aar_sha256 = hashlib.sha256(assets[contract.ANDROID_AAR]).hexdigest()
        manifest = {
            "assets": [
                {
                    "name": contract.ANDROID_AAR,
                    "sha256": aar_sha256,
                },
                {
                    "name": contract.ANDROID_MANIFEST,
                    "sha256": hashlib.sha256(
                        assets[contract.ANDROID_MANIFEST]
                    ).hexdigest(),
                },
                {
                    "bundle_manifest_sha256": "6" * 64,
                    "device": {
                        "abi": "arm64-v8a",
                        "kind": "emulator",
                        "page_size": 16_384,
                        "sdk": 35,
                    },
                    "name": contract.ANDROID_RUNTIME_BUNDLE,
                    "proof_sha256": "7" * 64,
                    "tested_aar_sha256": aar_sha256,
                },
            ]
        }
        assets[contract.RELEASE_MANIFEST] = _canonical_json(manifest)
        return assets, manifest

    def _assembly_receipt(
        self,
        transaction_name: str,
        assets: Mapping[str, bytes],
        manifest: Mapping[str, object],
    ) -> pathlib.Path:
        transaction = self.assembly_root / transaction_name
        transaction.mkdir(mode=0o700)
        os.chmod(transaction, 0o700)
        release = transaction / platform_distribution.PLATFORM_RELEASE_DIRECTORY_NAME
        release.mkdir(mode=0o755)
        os.chmod(release, 0o755)
        records: list[dict[str, object]] = []
        for name in contract.PUBLIC_ASSET_NAMES:
            data = assets[name]
            path = release / name
            path.write_bytes(data)
            os.chmod(path, 0o644)
            records.append(
                {
                    "bytes": len(data),
                    "content_type": contract.PUBLIC_ASSET_CONTENT_TYPES[name],
                    "name": name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        by_name = {record["name"]: record for record in records}
        runtime_record = next(
            item
            for item in manifest["assets"]
            if item["name"] == contract.ANDROID_RUNTIME_BUNDLE
        )
        receipt = {
            "android_runtime_evidence": {
                "bundle_manifest_sha256": runtime_record[
                    "bundle_manifest_sha256"
                ],
                "bundle_schema": contract.ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION,
                "bundle_sha256": by_name[contract.ANDROID_RUNTIME_BUNDLE][
                    "sha256"
                ],
                "device_abi": runtime_record["device"]["abi"],
                "device_kind": runtime_record["device"]["kind"],
                "device_sdk": runtime_record["device"]["sdk"],
                "page_size": runtime_record["device"]["page_size"],
                "proof_schema": contract.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
                "proof_sha256": runtime_record["proof_sha256"],
                "release_mode": True,
                "tested_aar_manifest_sha256": by_name[
                    contract.ANDROID_MANIFEST
                ]["sha256"],
                "tested_aar_sha256": runtime_record["tested_aar_sha256"],
            },
            "assets": records,
            "checksums_sha256": by_name[contract.RELEASE_SUMS]["sha256"],
            "kind": distribution_contract.PLATFORM_RELEASE_CANDIDATE_KIND,
            "platform_distribution_sha256": by_name[
                contract.RELEASE_MANIFEST
            ]["sha256"],
            "schema_version": (
                distribution_contract.PLATFORM_RELEASE_CANDIDATE_SCHEMA_VERSION
            ),
            "source": {
                "canonical_source_tree_sha256": self.SOURCE_DIGEST,
                "git_commit": self.TAG_COMMIT,
                "git_dirty": False,
                "git_tree": self.TAG_TREE,
                "source_date_epoch": self.source.source_date_epoch,
            },
        }
        path = transaction / platform_distribution.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
        path.write_bytes(_canonical_json(receipt))
        os.chmod(path, 0o600)
        return path

    def _candidate_and_assembly(
        self, name: str
    ) -> tuple[pathlib.Path, pathlib.Path, dict[str, bytes], dict[str, object]]:
        assets, manifest = self._asset_fixture()
        candidate = self._candidate_for_assets(f"candidate-{name}", assets)
        assembly = self._assembly_receipt(
            f"transaction.{name}", assets, manifest
        )
        return candidate, assembly, assets, manifest

    def _remote_fixture(
        self,
        assets: Mapping[str, bytes],
    ) -> tuple[
        dict[str, object], dict[str, object], dict[str, object], dict[str, object]
    ]:
        records = []
        for index, name in enumerate(reversed(contract.PUBLIC_ASSET_NAMES), start=1):
            data = assets[name]
            records.append(
                {
                    "apiUrl": f"{publication.API_ASSET_PREFIX}{1000 + index}",
                    "contentType": contract.PUBLIC_ASSET_CONTENT_TYPES[name],
                    "createdAt": "2026-08-14T01:30:00Z",
                    "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
                    "downloadCount": index,
                    "id": f"asset_{index}",
                    "label": "",
                    "name": name,
                    "size": len(data),
                    "state": "uploaded",
                    "updatedAt": "2026-08-14T01:45:00Z",
                    "url": (
                        f"{publication.RELEASE_DOWNLOAD_PREFIX}"
                        f"{contract.RELEASE_TAG}/{name}"
                    ),
                }
            )
        release_before: dict[str, object] = {
            "assets": records,
            "databaseId": self.RELEASE_ID,
            "isDraft": False,
            "isImmutable": True,
            "isPrerelease": False,
            "publishedAt": "2026-08-14T02:30:00Z",
            "tagName": contract.RELEASE_TAG,
            "targetCommitish": "main",
            "url": contract.RELEASE_URL,
        }
        release_after = copy.deepcopy(release_before)
        for asset in release_after["assets"]:
            asset["downloadCount"] += 1
        repository = {
            "nameWithOwner": publication.REPOSITORY,
            "url": publication.REPOSITORY_URL,
            "visibility": "PUBLIC",
        }
        by_name = {record["name"]: record for record in records}
        subjects = [
            {
                "digest": {"sha1": self.TAG_OBJECT},
                "uri": contract.TAG_SUBJECT_URI,
            },
            *[
                {
                    "digest": {
                        "sha256": by_name[name]["digest"].removeprefix(
                            "sha256:"
                        )
                    },
                    "name": name,
                }
                for name in contract.PUBLIC_ASSET_NAMES
            ],
        ]
        verification = {
            "attestation": {"fixture": "private raw bundle"},
            "verificationResult": {
                "mediaType": (
                    publication.github_release.VERIFICATION_RESULT_MEDIA_TYPE
                ),
                "signature": {
                    "certificate": {
                        "certificateIssuer": (
                            publication.github_release.RELEASE_CERTIFICATE_ISSUER
                        ),
                        "subjectAlternativeName": (
                            publication.github_release.RELEASE_CERTIFICATE_SAN
                        ),
                    }
                },
                "statement": {
                    "_type": publication.github_release.STATEMENT_TYPE,
                    "predicate": {
                        "databaseId": str(self.RELEASE_ID),
                        "ownerId": "149552943",
                        "packageId": "1279236693",
                        "purl": contract.TAG_SUBJECT_URI,
                        "repository": publication.REPOSITORY,
                        "repositoryId": "1279236693",
                        "tag": contract.RELEASE_TAG,
                    },
                    "predicateType": publication.github_release.RELEASE_PREDICATE_TYPE,
                    "subject": subjects,
                },
                "verifiedIdentity": {
                    "issuer": {"issuer": "", "regexp": ".*"},
                    "subjectAlternativeName": {
                        "regexp": r"^https://dotcom\.releases\.github\.com$",
                        "subjectAlternativeName": "",
                    },
                },
                "verifiedTimestamps": [
                    {
                        "timestamp": "2026-08-14T03:00:00Z",
                        "type": publication.github_release.TIMESTAMP_AUTHORITY_TYPE,
                        "uri": publication.github_release.TIMESTAMP_AUTHORITY_URI,
                    }
                ],
            },
        }
        return repository, release_before, release_after, verification

    def _candidate_for_assets(
        self, name: str, assets: Mapping[str, bytes]
    ) -> pathlib.Path:
        digests = {
            asset_name: hashlib.sha256(assets[asset_name]).hexdigest()
            for asset_name in contract.CANDIDATE_PUBLIC_ASSET_NAMES
        }
        parent = self._private_parent(self.candidate_root, name)
        path = parent / candidate_attestation.PROJECTION_NAME
        path.write_bytes(_canonical_json(self._candidate_projection_value(digests)))
        os.chmod(path, 0o600)
        return path

    def _collect_fixture(
        self,
        name: str,
        *,
        mutate_repository: Callable[[dict[str, object]], None] | None = None,
        mutate_release_before: Callable[[dict[str, object]], None] | None = None,
        mutate_release_after: Callable[[dict[str, object]], None] | None = None,
        mutate_verification: Callable[[dict[str, object]], None] | None = None,
        sink_mutation: Callable[[str, bytes], bytes] | None = None,
        deep_mutation: Callable[[], None] | None = None,
        remote_runner: RemoteFixtureRunner | None = None,
        before_collect: Callable[[], None] | None = None,
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, RemoteFixtureRunner, AssetSinkRunner]:
        assets, manifest = self._asset_fixture()
        candidate = self._candidate_for_assets(f"candidate-{name}", assets)
        pending = self._pending_receipt(
            name,
            candidate_path=candidate,
            assets=assets,
            manifest=manifest,
        )
        repository, before, after, verification = self._remote_fixture(assets)
        if mutate_repository is not None:
            mutate_repository(repository)
        if mutate_release_before is not None:
            mutate_release_before(before)
        if mutate_release_after is not None:
            mutate_release_after(after)
        if mutate_verification is not None:
            mutate_verification(verification)
        runner = remote_runner or RemoteFixtureRunner(
            repository_view=repository,
            release_before=before,
            release_after=after,
            verification=verification,
        )
        sink = AssetSinkRunner(assets, mutate=sink_mutation)
        raw = self.raw_root / f"raw-{name}"
        downloads = self.download_root / f"downloads-{name}"

        def deep_verifier(
            verifier_checkout: pathlib.Path,
            download_directory: pathlib.Path,
            tools: publication.AndroidVerificationTools,
            **kwargs: object,
        ) -> tuple[dict[str, Any], bytes]:
            self.assertEqual(self.verifier, verifier_checkout)
            self.assertEqual(downloads, download_directory)
            self.assertEqual(self.tools, tools)
            self.assertEqual(self.TAG_COMMIT, kwargs["expected_commit"])
            if deep_mutation is not None:
                deep_mutation()
            return copy.deepcopy(manifest), (
                "ABI2_PLATFORM_DISTRIBUTION_VERIFY_PASS "
                f"commit={self.TAG_COMMIT} assets=5\n"
            ).encode("ascii")

        if before_collect is not None:
            before_collect()
        output, _digest, _release_id = publication.collect_verified_receipt(
            pending,
            self.verifier,
            raw,
            downloads,
            android_tools=self.tools,
            runner=runner,
            sink_runner=sink,
            clock=QueueClock(
                "2026-08-14T04:00:00Z", "2026-08-14T05:00:00Z"
            ),
            monotonic=lambda: 100.0,
            source_environment={"GH_TOKEN": "fixture-token"},
            git_tool="/usr/bin/git",
            source_inspector=self._source_inspector,
            deep_verifier=deep_verifier,
        )
        pending_value = json.loads(pending.read_bytes())
        verified_value = json.loads(output.read_bytes())
        for field in ("source", "candidate_attestation", "release_candidate"):
            self.assertEqual(
                pending_value["observation"][field],
                verified_value["observation"][field],
            )
        return output, raw, downloads, runner, sink

    def test_pending_receipt_is_exact_private_and_attempt_two_valid(self) -> None:
        output = self._pending_receipt("pending-exact")

        receipt = json.loads(output.read_bytes())
        contract.validate_v0_1_3_publication_receipt(receipt)
        self.assertEqual(contract.PLATFORM_V0_1_3_STATUS_PENDING, receipt["status"])
        self.assertEqual(
            {
                "assembly_receipt_sha256",
                "candidate_attestation",
                "observed_at",
                "release_candidate",
                "source",
            },
            set(receipt["observation"]),
        )
        self.assertEqual(
            2,
            receipt["observation"]["candidate_attestation"][
                "workflow_run_attempt"
            ],
        )
        self.assertEqual(self.source.document(), receipt["observation"]["source"])
        self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
        self.assertEqual(1, output.stat().st_nlink)

    def test_pending_resamples_assembly_transaction_before_receipt_commit(self) -> None:
        candidate, assembly, _assets, _manifest = self._candidate_and_assembly(
            "pending-resample"
        )
        real_load = platform_distribution.load_release_candidate_bundle
        calls = 0

        def load_and_mutate(
            path: pathlib.Path,
        ) -> platform_distribution.ReleaseCandidateBundle:
            nonlocal calls
            calls += 1
            value = real_load(path)
            if calls == 1:
                release = (
                    path.parent
                    / platform_distribution.PLATFORM_RELEASE_DIRECTORY_NAME
                )
                asset = release / contract.ANDROID_AAR
                asset.write_bytes(b"changed after first pending sample")
                os.chmod(asset, 0o644)
            return value

        before = set(self.receipt_root.iterdir())
        with (
            mock.patch.object(
                platform_distribution,
                "load_release_candidate_bundle",
                side_effect=load_and_mutate,
            ),
            self.assertRaises(publication.PlatformV013PublicationError),
        ):
            publication.assemble_pending_receipt(
                candidate,
                assembly,
                self.verifier,
                runner=lambda *_args, **_kwargs: BoundedResult(0),
                clock=QueueClock("2026-08-14T02:00:00Z"),
                source_environment={},
                git_tool="/usr/bin/git",
                source_inspector=self._source_inspector,
            )
        self.assertEqual(2, calls)
        self.assertEqual(before, set(self.receipt_root.iterdir()))

    def test_cli_markers_identify_receipt_digest_for_both_states(self) -> None:
        output = self.root / "platform-v0.1.3-publication-receipt.json"

        pending_arguments = mock.Mock(
            command="pending",
            candidate_projection=self.root / "candidate.json",
            assembly_receipt=self.root / "assembly.json",
            verifier_checkout=self.verifier,
        )
        pending_parser = mock.Mock()
        pending_parser.parse_args.return_value = pending_arguments
        pending_stdout = io.StringIO()
        with (
            mock.patch.object(publication, "build_parser", return_value=pending_parser),
            mock.patch.object(
                publication,
                "assemble_pending_receipt",
                return_value=(output, "a" * 64, self.source),
            ),
            mock.patch.object(
                publication,
                "_relative_output",
                return_value="target/pending/receipt.json",
            ),
            contextlib.redirect_stdout(pending_stdout),
        ):
            self.assertEqual(0, publication.main(["pending"]))
        self.assertIn(f"receipt_sha256={'a' * 64}", pending_stdout.getvalue())
        self.assertNotIn("projection_sha256=", pending_stdout.getvalue())

        verified_arguments = mock.Mock(
            command="collect",
            pending_receipt=self.root / "pending.json",
            verifier_checkout=self.verifier,
            raw_directory=self.raw_root / "raw-cli",
            download_directory=self.download_root / "downloads-cli",
            android_llvm_nm=self.tools.llvm_nm,
            android_llvm_readelf=self.tools.llvm_readelf,
            android_apksigner=self.tools.apksigner,
            android_zipalign=self.tools.zipalign,
        )
        verified_parser = mock.Mock()
        verified_parser.parse_args.return_value = verified_arguments
        verified_stdout = io.StringIO()
        with (
            mock.patch.object(
                publication, "build_parser", return_value=verified_parser
            ),
            mock.patch.object(
                publication,
                "collect_verified_receipt",
                return_value=(output, "b" * 64, self.RELEASE_ID),
            ),
            mock.patch.object(
                publication,
                "_relative_output",
                return_value="target/verified/receipt.json",
            ),
            contextlib.redirect_stdout(verified_stdout),
        ):
            self.assertEqual(0, publication.main(["collect"]))
        self.assertIn(f"receipt_sha256={'b' * 64}", verified_stdout.getvalue())
        self.assertNotIn("projection_sha256=", verified_stdout.getvalue())

    def test_pending_cli_requires_the_assembly_receipt(self) -> None:
        parser = publication.build_parser()
        parsed = parser.parse_args(
            [
                "pending",
                "--candidate-projection",
                "/candidate.json",
                "--assembly-receipt",
                "/assembly.json",
                "--verifier-checkout",
                "/verifier",
            ]
        )
        self.assertEqual(pathlib.Path("/assembly.json"), parsed.assembly_receipt)
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            parser.parse_args(
                [
                    "pending",
                    "--candidate-projection",
                    "/candidate.json",
                    "--verifier-checkout",
                    "/verifier",
                ]
            )

    def test_cli_preserves_structured_and_incomplete_committed_errors(self) -> None:
        structured = publication.PublicationReceiptCommittedError(
            "fixture committed",
            leaf=publication.RECEIPT_NAME,
            digest="a" * 64,
        )
        collect_arguments = mock.Mock(
            command="collect",
            pending_receipt=self.root / "pending.json",
            verifier_checkout=self.verifier,
            raw_directory=self.raw_root / "raw-cli-committed",
            download_directory=self.download_root / "downloads-cli-committed",
            android_llvm_nm=self.tools.llvm_nm,
            android_llvm_readelf=self.tools.llvm_readelf,
            android_apksigner=self.tools.apksigner,
            android_zipalign=self.tools.zipalign,
        )
        collect_parser = mock.Mock()
        collect_parser.parse_args.return_value = collect_arguments
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                publication,
                "build_parser",
                return_value=collect_parser,
            ),
            mock.patch.object(
                publication,
                "collect_verified_receipt",
                side_effect=structured,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(125, publication.main(["collect"]))
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "PUBLICATION_RECEIPT_COMMITTED_ERROR "
            "visibility=committed "
            f"leaf={publication.RECEIPT_NAME} sha256={'a' * 64}\n",
            stderr.getvalue(),
        )
        self.assertNotIn("PASS", stdout.getvalue() + stderr.getvalue())

        indeterminate = publication.PublicationReceiptCommittedError(
            "fixture indeterminate visibility",
            leaf=publication.RECEIPT_NAME,
            digest="b" * 64,
            visibility="indeterminate",
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                publication,
                "build_parser",
                return_value=collect_parser,
            ),
            mock.patch.object(
                publication,
                "collect_verified_receipt",
                side_effect=indeterminate,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(125, publication.main(["collect"]))
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "PUBLICATION_RECEIPT_COMMITTED_ERROR "
            "visibility=indeterminate "
            f"leaf={publication.RECEIPT_NAME} sha256={'b' * 64}\n",
            stderr.getvalue(),
        )
        self.assertNotIn("PASS", stdout.getvalue() + stderr.getvalue())

        incomplete = publication.PublicationReceiptCommittedError(
            "fixture incomplete committed state"
        )
        pending_arguments = mock.Mock(
            command="pending",
            candidate_projection=self.root / "candidate.json",
            verifier_checkout=self.verifier,
        )
        pending_parser = mock.Mock()
        pending_parser.parse_args.return_value = pending_arguments
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                publication,
                "build_parser",
                return_value=pending_parser,
            ),
            mock.patch.object(
                publication,
                "assemble_pending_receipt",
                side_effect=incomplete,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(125, publication.main(["pending"]))
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "error: publication receipt committed with incomplete durability\n",
            stderr.getvalue(),
        )
        self.assertNotIn(
            "PUBLICATION_RECEIPT_COMMITTED_ERROR",
            stderr.getvalue(),
        )
        self.assertNotIn("PASS", stdout.getvalue() + stderr.getvalue())

    def test_fixed_root_bootstrap_accepts_owned_0775_parent_only(self) -> None:
        bootstrap = self.root / "bootstrap-target"
        bootstrap.mkdir(mode=0o775)
        os.chmod(bootstrap, 0o775)
        receipt_root = bootstrap / "receipts"
        verification_root = bootstrap / "verification"
        raw_root = verification_root / "raw"
        download_root = verification_root / "downloads"
        worktree_root = bootstrap / "worktrees"
        patches = (
            ("PLATFORM_PUBLICATION_RECEIPT_ROOT", receipt_root),
            ("PLATFORM_PUBLICATION_VERIFICATION_ROOT", verification_root),
            ("PLATFORM_PUBLICATION_RAW_ROOT", raw_root),
            ("PLATFORM_PUBLICATION_DOWNLOAD_ROOT", download_root),
            ("PLATFORM_PUBLICATION_WORKTREE_ROOT", worktree_root),
        )
        with mock.patch.multiple(publication, **dict(patches)):
            publication._ensure_platform_safe_roots()
        for path in (
            receipt_root,
            verification_root,
            raw_root,
            download_root,
            worktree_root,
        ):
            self.assertTrue(path.is_dir())
            self.assertFalse(path.is_symlink())
            self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode))

        unsafe_parent = self.root / "world-writable-target"
        unsafe_parent.mkdir(mode=0o777)
        os.chmod(unsafe_parent, 0o777)
        with mock.patch.object(
            publication,
            "PLATFORM_PUBLICATION_RECEIPT_ROOT",
            unsafe_parent / "receipts",
        ):
            with self.assertRaisesRegex(
                publication.PlatformV013PublicationError,
                "non-world-writable",
            ):
                publication._ensure_platform_safe_roots()

        actual_parent = self.root / "actual-target"
        actual_parent.mkdir(mode=0o775)
        os.chmod(actual_parent, 0o775)
        symlink_parent = self.root / "target-link"
        symlink_parent.symlink_to(actual_parent, target_is_directory=True)
        with mock.patch.object(
            publication,
            "PLATFORM_PUBLICATION_RECEIPT_ROOT",
            symlink_parent / "receipts",
        ):
            with self.assertRaises(publication.PlatformV013PublicationError):
                publication._ensure_platform_safe_roots()

    def test_verified_transaction_uses_exact_bounded_commands_and_private_bytes(self) -> None:
        output, raw, downloads, runner, sink = self._collect_fixture("valid")

        receipt_bytes = output.read_bytes()
        receipt = json.loads(receipt_bytes)
        contract.validate_v0_1_3_publication_receipt(receipt)
        self.assertEqual(contract.PLATFORM_V0_1_3_STATUS_VERIFIED, receipt["status"])
        self.assertEqual(self.RELEASE_ID, receipt["observation"]["release_id"])
        self.assertEqual(self.source.document(), receipt["observation"]["source"])
        self.assertEqual(
            2,
            receipt["observation"]["candidate_attestation"][
                "workflow_run_attempt"
            ],
        )
        self.assertFalse(
            receipt["observation"]["fresh_download_verification"].get(
                "anonymous_availability_verified", False
            )
        )
        self.assertNotIn(str(self.root), receipt_bytes.decode("ascii"))
        self.assertEqual(
            publication.RAW_NAMES,
            {entry.name for entry in raw.iterdir()},
        )
        for entry in raw.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(entry.stat().st_mode))
            self.assertEqual(1, entry.stat().st_nlink)
        self.assertEqual(
            set(contract.PUBLIC_ASSET_NAMES),
            {entry.name for entry in downloads.iterdir()},
        )
        for entry in downloads.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(entry.stat().st_mode))
            self.assertEqual(1, entry.stat().st_nlink)
            self.assertTrue(entry.is_file())
            self.assertFalse(entry.is_symlink())
        self.assertEqual(5, len(runner.calls))
        self.assertEqual(len(contract.PUBLIC_ASSET_NAMES), len(sink.calls))
        self.select_github_cli.assert_called_once_with()
        self.assertEqual(
            2 * (len(runner.calls) + len(sink.calls)),
            self.resample_github_cli.call_count,
        )
        for command, name in zip(sink.calls, contract.PUBLIC_ASSET_NAMES, strict=True):
            self.assertEqual(
                (
                    "/fixture/gh",
                    "release",
                    "download",
                    contract.RELEASE_TAG,
                    "--repo",
                    publication.GH_REPOSITORY_ARGUMENT,
                    "--pattern",
                    name,
                    "--output",
                    "-",
                ),
                command,
            )

    def test_release_repository_and_attestation_mutations_fail_closed(self) -> None:
        cases: tuple[
            tuple[
                str,
                dict[str, Callable[[dict[str, object]], None]],
            ],
            ...,
        ] = (
            (
                "private-repository",
                {"mutate_repository": lambda value: value.update(visibility="PRIVATE")},
            ),
            (
                "mutable-release",
                {"mutate_release_before": lambda value: value.update(isImmutable=False)},
            ),
            (
                "extra-asset",
                {
                    "mutate_release_before": lambda value: value["assets"].append(
                        copy.deepcopy(value["assets"][0])
                    )
                },
            ),
            (
                "candidate-size",
                {
                    "mutate_release_before": lambda value: value["assets"][0].update(
                        size=value["assets"][0]["size"] + 1
                    )
                },
            ),
            (
                "candidate-content-type",
                {
                    "mutate_release_before": lambda value: value["assets"][0].update(
                        contentType="application/x-unexpected"
                    )
                },
            ),
            (
                "attestation-subject",
                {
                    "mutate_verification": lambda value: value[
                        "verificationResult"
                    ]["statement"]["subject"][1]["digest"].update(
                        sha256="f" * 64
                    )
                },
            ),
            (
                "post-view-drift",
                {
                    "mutate_release_after": lambda value: value.update(
                        publishedAt="2026-08-14T02:31:00Z"
                    )
                },
            ),
        )
        for name, mutations in cases:
            with self.subTest(name=name):
                verified_before = set(
                    self.receipt_root.glob("transaction.verified.*")
                )
                with self.assertRaises(publication.PlatformV013PublicationError):
                    self._collect_fixture(name, **mutations)
                self.assertEqual(
                    verified_before,
                    set(self.receipt_root.glob("transaction.verified.*")),
                )

    def test_download_digest_mismatch_fails_without_verified_projection(self) -> None:
        def mutate(name: str, data: bytes) -> bytes:
            if name == contract.ANDROID_AAR:
                return bytes([data[0] ^ 1]) + data[1:]
            return data

        verified_before = set(self.receipt_root.glob("transaction.verified.*"))
        with self.assertRaises(publication.PlatformV013PublicationError):
            self._collect_fixture("download-mismatch", sink_mutation=mutate)
        self.assertEqual(
            verified_before,
            set(self.receipt_root.glob("transaction.verified.*")),
        )

    def test_final_raw_inventory_rejects_byte_drift(self) -> None:
        _output, raw, _downloads, _runner, _sink = self._collect_fixture(
            "raw-byte-drift"
        )
        expected = {
            entry.name: hashlib.sha256(entry.read_bytes()).hexdigest()
            for entry in raw.iterdir()
        }
        changed = raw / publication.RAW_RELEASE_BEFORE_NAME
        changed.write_bytes(b'{"changed":true}\n')
        os.chmod(changed, 0o600)

        with self.assertRaisesRegex(
            publication.PlatformV013PublicationError,
            "raw bytes changed",
        ):
            with publication.open_private_direct_child_handle(
                safe_root=self.raw_root,
                direct_child_name=raw.name,
                label="fixture raw transaction",
            ) as raw_handle:
                publication._validate_raw_directory(raw_handle, expected)

    def test_android_tool_drift_during_deep_verification_fails_closed(self) -> None:
        verified_before = set(self.receipt_root.glob("transaction.verified.*"))

        def mutate_tool() -> None:
            self.tools.llvm_nm.write_bytes(b"changed llvm-nm fixture\n")

        with self.assertRaisesRegex(
            publication.PlatformV013PublicationError,
            "Android verification tools changed",
        ):
            self._collect_fixture(
                "android-tool-drift",
                deep_mutation=mutate_tool,
            )
        self.assertEqual(
            verified_before,
            set(self.receipt_root.glob("transaction.verified.*")),
        )

    def test_pinned_raw_directory_swap_during_deep_fails_closed(self) -> None:
        raw = self.raw_root / "raw-pinned-swap"
        moved = self.raw_root / "raw-pinned-swap-moved"
        verified_before = set(self.receipt_root.glob("transaction.verified.*"))

        def swap_raw_directory() -> None:
            raw.rename(moved)
            raw.mkdir(mode=0o700)
            os.chmod(raw, 0o700)

        with self.assertRaisesRegex(
            publication.PlatformV013PublicationError,
            "identity changed while pinned",
        ):
            self._collect_fixture(
                "pinned-swap",
                deep_mutation=swap_raw_directory,
            )
        self.assertEqual(
            verified_before,
            set(self.receipt_root.glob("transaction.verified.*")),
        )

    def test_raw_swap_at_commit_window_leaves_receipt_root_unchanged(self) -> None:
        raw = self.raw_root / "raw-commit-window"
        moved = self.raw_root / "raw-commit-window-moved"

        def receipt_snapshot() -> dict[pathlib.Path, bytes | None]:
            return {
                path.relative_to(self.receipt_root): (
                    path.read_bytes() if path.is_file() else None
                )
                for path in self.receipt_root.rglob("*")
            }

        before: dict[pathlib.Path, bytes | None] | None = None

        def capture_before() -> None:
            nonlocal before
            before = receipt_snapshot()
        real_validate = publication.validate_v0_1_3_publication_receipt
        swapped = False

        def validate_and_swap(value: object) -> None:
            nonlocal swapped
            real_validate(value)
            if (
                not swapped
                and isinstance(value, dict)
                and value.get("status") == contract.PLATFORM_V0_1_3_STATUS_VERIFIED
            ):
                swapped = True
                raw.rename(moved)
                raw.mkdir(mode=0o700)
                os.chmod(raw, 0o700)

        with (
            mock.patch.object(
                publication,
                "validate_v0_1_3_publication_receipt",
                side_effect=validate_and_swap,
            ),
            self.assertRaisesRegex(
                publication.PlatformV013PublicationError,
                "identity changed while pinned",
            ),
        ):
            self._collect_fixture(
                "commit-window",
                before_collect=capture_before,
            )
        self.assertTrue(swapped)
        self.assertIsNotNone(before)
        self.assertEqual(before, receipt_snapshot())

    def test_retryable_remote_failure_is_not_retried(self) -> None:
        assets, manifest = self._asset_fixture()
        candidate = self._candidate_for_assets("candidate-retryable", assets)
        pending = self._pending_receipt(
            "retryable",
            candidate_path=candidate,
            assets=assets,
            manifest=manifest,
        )
        calls: list[tuple[str, ...]] = []

        def failed_runner(argv: Sequence[str], **_kwargs: object) -> BoundedResult:
            calls.append(tuple(argv))
            return BoundedResult(1)

        verified_before = set(self.receipt_root.glob("transaction.verified.*"))
        with self.assertRaisesRegex(
            publication.PlatformV013PublicationRetryableError,
            r"^retryable:github-command-nonzero$",
        ):
            publication.collect_verified_receipt(
                pending,
                self.verifier,
                self.raw_root / "raw-retryable",
                self.download_root / "downloads-retryable",
                android_tools=self.tools,
                runner=failed_runner,
                source_environment={"GH_TOKEN": "fixture-token"},
                git_tool="/usr/bin/git",
                source_inspector=self._source_inspector,
            )
        self.assertEqual(1, len(calls))
        self.assertEqual(
            verified_before,
            set(self.receipt_root.glob("transaction.verified.*")),
        )

    def test_generated_transactions_never_clobber_previous_receipts(self) -> None:
        candidate, assembly, _assets, _manifest = self._candidate_and_assembly(
            "generated-shared"
        )
        first = self._pending_receipt(
            "generated-first",
            candidate_path=candidate,
            assembly_receipt=assembly,
        )
        first_bytes = first.read_bytes()
        second = self._pending_receipt(
            "generated-second",
            candidate_path=candidate,
            assembly_receipt=assembly,
        )

        self.assertNotEqual(first, second)
        self.assertEqual(first_bytes, first.read_bytes())
        self.assertTrue(second.is_file())

    def test_shared_atomic_writer_failure_leaves_no_partial_and_recovers(self) -> None:
        candidate, assembly, _assets, _manifest = self._candidate_and_assembly(
            "atomic-failure"
        )
        before = set(self.receipt_root.iterdir())
        with mock.patch.object(
            publication,
            "create_private_transaction_json",
            side_effect=publication.PublicationReceiptIOError(
                "injected atomic receipt failure"
            ),
        ):
            with self.assertRaisesRegex(
                publication.PlatformV013PublicationError,
                "injected atomic receipt failure",
            ):
                publication.assemble_pending_receipt(
                    candidate,
                    assembly,
                    self.verifier,
                    runner=lambda *_args, **_kwargs: BoundedResult(0),
                    clock=QueueClock("2026-08-14T02:00:00Z"),
                    source_environment={},
                    git_tool="/usr/bin/git",
                    source_inspector=self._source_inspector,
                )
        self.assertEqual(before, set(self.receipt_root.iterdir()))

        output, _digest, _source = publication.assemble_pending_receipt(
            candidate,
            assembly,
            self.verifier,
            runner=lambda *_args, **_kwargs: BoundedResult(0),
            clock=QueueClock("2026-08-14T02:00:00Z"),
            source_environment={},
            git_tool="/usr/bin/git",
            source_inspector=self._source_inspector,
        )
        self.assertTrue(output.is_file())

    def test_receipt_committed_error_is_not_downgraded(self) -> None:
        candidate, assembly, _assets, _manifest = self._candidate_and_assembly(
            "committed-error"
        )
        committed = publication.PublicationReceiptCommittedError(
            "fixture receipt committed",
            leaf=publication.RECEIPT_NAME,
            digest="a" * 64,
        )
        with (
            mock.patch.object(
                publication,
                "create_private_transaction_json",
                side_effect=committed,
            ),
            self.assertRaises(
                publication.PublicationReceiptCommittedError
            ) as caught,
        ):
            publication.assemble_pending_receipt(
                candidate,
                assembly,
                self.verifier,
                runner=lambda *_args, **_kwargs: BoundedResult(0),
                clock=QueueClock("2026-08-14T02:00:00Z"),
                source_environment={},
                git_tool="/usr/bin/git",
                source_inspector=self._source_inspector,
            )
        self.assertIs(committed, caught.exception)

    def test_platform_writer_detects_same_bytes_rename_competitor(self) -> None:
        pending = self._pending_receipt("writer-competitor")
        receipt = json.loads(pending.read_bytes())
        payload = receipt_io.canonical_json_bytes(receipt)
        real_rename = receipt_io._rename_noreplace

        def replace_after_rename(
            directory_fd: int,
            source_leaf: str,
            destination_leaf: str,
        ) -> None:
            real_rename(directory_fd, source_leaf, destination_leaf)
            os.unlink(destination_leaf, dir_fd=directory_fd)
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

        with (
            mock.patch.object(
                receipt_io,
                "_rename_noreplace",
                side_effect=replace_after_rename,
            ),
            self.assertRaises(
                publication.PublicationReceiptCommittedError
            ) as caught,
        ):
            publication._write_receipt(
                receipt,
                transaction_prefix="transaction.pending.",
            )
        self.assertEqual(publication.RECEIPT_NAME, caught.exception.leaf)
        matching = [
            path
            for path in self.receipt_root.glob(
                f"transaction.pending.*/{publication.RECEIPT_NAME}"
            )
            if path != pending
        ]
        self.assertEqual(1, len(matching))
        self.assertEqual(payload, matching[0].read_bytes())

        raw = self.raw_root / "raw-atomic-failure"
        with publication.create_private_direct_child_handle(
            safe_root=self.raw_root,
            direct_child_name=raw.name,
            label="fixture raw transaction",
        ) as raw_handle:
            raw_leaf = publication.RAW_REPOSITORY_BEFORE_NAME
            with mock.patch.object(
                publication,
                "write_private_bytes_noreplace_at",
                side_effect=publication.PublicationReceiptIOError(
                    "injected atomic raw failure"
                ),
            ):
                with self.assertRaisesRegex(
                    publication.PlatformV013PublicationError,
                    "injected atomic raw failure",
                ):
                    publication._write_raw(
                        raw_handle,
                        raw_leaf,
                        b'{"visibility":"PUBLIC"}\n',
                        label="fixture raw evidence",
                    )
            self.assertFalse((raw / raw_leaf).exists())
            self.assertEqual([], list(raw.glob(f".{raw_leaf}.pending-*")))
            publication._write_raw(
                raw_handle,
                raw_leaf,
                b'{"visibility":"PUBLIC"}\n',
                label="fixture raw evidence",
            )
        self.assertEqual(
            b'{"visibility":"PUBLIC"}\n', (raw / raw_leaf).read_bytes()
        )

    def test_fresh_inventory_rejects_extra_symlink_fifo_and_hardlink(self) -> None:
        assets, _manifest = self._asset_fixture()
        expected = {
            name: {
                "bytes": len(data),
                "name": name,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in assets.items()
        }

        def prepare(case: str) -> pathlib.Path:
            directory = self.download_root / f"inventory-{case}"
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
            for name, data in assets.items():
                path = directory / name
                path.write_bytes(data)
                os.chmod(path, 0o600)
            return directory

        for case in ("extra", "symlink", "fifo", "hardlink"):
            with self.subTest(case=case):
                directory = prepare(case)
                selected = directory / contract.PUBLIC_ASSET_NAMES[0]
                if case == "extra":
                    extra = directory / "unexpected.bin"
                    extra.write_bytes(b"extra\n")
                    os.chmod(extra, 0o600)
                elif case == "symlink":
                    selected.unlink()
                    selected.symlink_to(directory / contract.PUBLIC_ASSET_NAMES[1])
                elif case == "fifo":
                    selected.unlink()
                    os.mkfifo(selected, 0o600)
                else:
                    os.link(selected, directory / "hardlink-copy")
                with self.assertRaises(publication.PlatformV013PublicationError):
                    with publication.open_private_direct_child_handle(
                        safe_root=self.download_root,
                        direct_child_name=directory.name,
                        label="fixture fresh download directory",
                    ) as handle:
                        publication._inventory_fresh_downloads(handle, expected)

    def test_fresh_inventory_uses_one_pinned_fd_and_resamples_entries(self) -> None:
        assets, _manifest = self._asset_fixture()
        expected = {
            name: {
                "bytes": len(data),
                "name": name,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in assets.items()
        }
        directory = self.download_root / "inventory-held-fd"
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
        for name, data in assets.items():
            path = directory / name
            path.write_bytes(data)
            os.chmod(path, 0o600)

        observed_descriptors: list[int] = []
        real_consume = publication.consume_regular_snapshot_at

        def consume_and_inject(
            directory_fd: int,
            leaf: str,
            **kwargs: object,
        ):
            observed_descriptors.append(directory_fd)
            digest = real_consume(directory_fd, leaf, **kwargs)
            if len(observed_descriptors) == len(contract.PUBLIC_ASSET_NAMES):
                extra = directory / "injected-after-snapshot"
                extra.write_bytes(b"changed directory inventory\n")
                os.chmod(extra, 0o600)
            return digest

        with publication.open_private_direct_child_handle(
            safe_root=self.download_root,
            direct_child_name=directory.name,
            label="fixture fresh download directory",
        ) as handle:
            with (
                mock.patch.object(
                    publication,
                    "consume_regular_snapshot_at",
                    side_effect=consume_and_inject,
                ),
                self.assertRaisesRegex(
                    publication.PlatformV013PublicationError,
                    "safely inventory",
                ),
            ):
                publication._inventory_fresh_downloads(handle, expected)
        self.assertEqual(len(contract.PUBLIC_ASSET_NAMES), len(observed_descriptors))
        self.assertEqual(1, len(set(observed_descriptors)))

    def test_direct_child_normalization_rejects_root_siblings_and_depth(self) -> None:
        sibling = self.root / "raw-evil"
        sibling.mkdir(mode=0o700)
        os.chmod(sibling, 0o700)
        deeper = self.raw_root / "parent" / "child"
        for unsafe in (
            self.raw_root,
            sibling,
            deeper,
            self.raw_root / "child" / ".." / "other",
            pathlib.Path("relative-child"),
        ):
            with self.subTest(path=unsafe):
                with self.assertRaises(publication.PlatformV013PublicationError):
                    publication._normalize_direct_child(
                        unsafe,
                        safe_root=self.raw_root,
                        label="fixture raw directory",
                        must_exist=False,
                    )

    def test_fixed_roots_reject_prefix_traversal_and_symlink_aliases(self) -> None:
        candidate = self._candidate_projection("safe-path-candidate")
        _valid_candidate, assembly, _assets, _manifest = (
            self._candidate_and_assembly("safe-path-assembly")
        )
        receipt_directories = set(self.receipt_root.iterdir())
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        link = self.candidate_root / "candidate-link"
        link.symlink_to(outside, target_is_directory=True)
        evil = self.root / "candidate-projections-evil"
        evil.mkdir(mode=0o700)
        unsafe_paths = (
            pathlib.Path("relative") / candidate_attestation.PROJECTION_NAME,
            link / candidate_attestation.PROJECTION_NAME,
            evil / candidate_attestation.PROJECTION_NAME,
            self.candidate_root
            / "child"
            / ".."
            / ".."
            / "outside"
            / candidate_attestation.PROJECTION_NAME,
        )
        for unsafe in unsafe_paths:
            with self.subTest(path=unsafe):
                with self.assertRaises(publication.PlatformV013PublicationError):
                    publication.assemble_pending_receipt(
                        unsafe,
                        assembly,
                        self.verifier,
                        source_environment={},
                        git_tool="/usr/bin/git",
                        source_inspector=self._source_inspector,
                    )
                self.assertEqual(receipt_directories, set(self.receipt_root.iterdir()))
        self.assertTrue(candidate.exists())

    def test_deep_verifier_command_is_loaded_from_tagged_checkout(self) -> None:
        artifact = self.verifier / "artifact"
        artifact.mkdir(mode=0o700)
        runner_script = artifact / "python-run.sh"
        verifier_module = artifact / "platform_distribution.py"
        runner_script.write_bytes(b"#!/bin/sh\n")
        verifier_module.write_bytes(b"# fixture\n")
        os.chmod(runner_script, 0o700)
        os.chmod(verifier_module, 0o600)
        downloads = self.download_root / "deep-command"
        downloads.mkdir(mode=0o700)
        os.chmod(downloads, 0o700)
        manifest = {"assets": []}
        manifest_path = downloads / contract.RELEASE_MANIFEST
        manifest_path.write_bytes(_canonical_json(manifest))
        os.chmod(manifest_path, 0o600)
        calls: list[tuple[str, ...]] = []

        def runner(argv: Sequence[str], **_kwargs: object) -> BoundedResult:
            calls.append(tuple(argv))
            return BoundedResult(
                0,
                (
                    "ABI2_PLATFORM_DISTRIBUTION_VERIFY_PASS "
                    f"commit={self.TAG_COMMIT} assets=5\n"
                ).encode("ascii"),
            )

        with publication.open_private_direct_child_handle(
            safe_root=self.download_root,
            direct_child_name=downloads.name,
            label="fixture fresh download directory",
        ) as download_handle:
            parsed, stdout = publication._run_deep_distribution_verifier(
                self.verifier,
                downloads,
                self.tools,
                download_directory_handle=download_handle,
                expected_commit=self.TAG_COMMIT,
                environment={},
                runner=runner,
            )
        self.assertEqual(manifest, parsed)
        self.assertIn(self.TAG_COMMIT.encode("ascii"), stdout)
        self.assertEqual(1, len(calls))
        command = calls[0]
        self.assertEqual("/bin/sh", command[0])
        self.assertEqual(str(runner_script), command[1])
        self.assertEqual("artifact/platform_distribution.py", command[2])
        self.assertIn(str(self.verifier), command)
        self.assertIn(str(downloads), command)

    def test_real_source_inspector_requires_clean_annotated_tag_checkout(self) -> None:
        # Replace the fixture .git directory with a small real standalone clone.
        (self.verifier / ".git").rmdir()
        subprocess.run(
            ["/usr/bin/git", "init", "-q", str(self.verifier)],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "config",
                "user.name",
                "Release Test",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "config",
                "user.email",
                "release@example.invalid",
            ],
            check=True,
        )
        source_file = self.verifier / "source.txt"
        source_file.write_text("tagged source\n", encoding="ascii")
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.verifier), "add", "source.txt"],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "commit",
                "-q",
                "-m",
                "source fixture",
            ],
            check=True,
        )
        source_parent_commit = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "rev-parse",
                "HEAD",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        source_digest = publication.canonical_tree_digest(
            self.verifier,
            publication.repository_paths(self.verifier),
        )
        artifact = self.verifier / "artifact"
        artifact.mkdir()
        (artifact / "results.json").write_bytes(
            _canonical_json(
                {
                    "proof_source_tree_sha256": source_digest,
                    "provenance": {
                        "snapshot_commit": source_parent_commit,
                    },
                }
            )
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "add",
                "artifact/results.json",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "commit",
                "-q",
                "-m",
                "results-only fixture",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "tag",
                "-a",
                contract.RELEASE_TAG,
                "-m",
                "release fixture tag",
            ],
            check=True,
        )
        environment = publication._git_environment({})

        observed = publication.inspect_verifier_source(
            self.verifier,
            git="/usr/bin/git",
            environment=environment,
            runner=capture_stdout,
        )

        self.assertEqual(observed.tag_commit, observed.verifier_commit)
        self.assertEqual(source_parent_commit, observed.source_parent_commit)
        self.assertNotEqual(observed.tag_object, observed.tag_commit)
        self.assertRegex(observed.canonical_source_tree_sha256, r"^[0-9a-f]{64}$")
        source_file.write_text("dirty source\n", encoding="ascii")
        with self.assertRaisesRegex(
            publication.PlatformV013PublicationError, "dirty"
        ):
            publication.inspect_verifier_source(
                self.verifier,
                git="/usr/bin/git",
                environment=environment,
                runner=capture_stdout,
            )

        # A second excluded file must not be hidden by the canonical source
        # digest.  Rebuild the tagged child from the same S with exactly that
        # forbidden extra mutation and require the shared Git transition gate
        # to reject it.
        source_file.write_text("tagged source\n", encoding="ascii")
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "checkout",
                "-q",
                "--detach",
                source_parent_commit,
            ],
            check=True,
        )
        artifact.mkdir(exist_ok=True)
        (artifact / "results.json").write_bytes(
            _canonical_json(
                {
                    "proof_source_tree_sha256": source_digest,
                    "provenance": {"snapshot_commit": source_parent_commit},
                }
            )
        )
        paper = self.verifier / "paper"
        paper.mkdir()
        (paper / "camera-ready-results.txt").write_text(
            "forbidden second result\n", encoding="ascii"
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "add",
                "artifact/results.json",
                "paper/camera-ready-results.txt",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "commit",
                "-q",
                "-m",
                "invalid two-file results fixture",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "tag",
                "-d",
                contract.RELEASE_TAG,
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.verifier),
                "tag",
                "-a",
                contract.RELEASE_TAG,
                "-m",
                "invalid release fixture tag",
            ],
            check=True,
        )
        with self.assertRaisesRegex(
            publication.PlatformV013PublicationError,
            "direct results-only child",
        ):
            publication.inspect_verifier_source(
                self.verifier,
                git="/usr/bin/git",
                environment=environment,
                runner=capture_stdout,
            )


if __name__ == "__main__":
    unittest.main()
