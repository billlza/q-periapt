#!/usr/bin/env python3
"""Focused transaction and mutation tests for alpha.3 publication collection."""

from __future__ import annotations

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
import platform_alpha3_publication as publication
import platform_alpha3_publication_contract as contract
import platform_candidate_attestation as candidate_attestation


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


class PlatformAlpha3PublicationTests(unittest.TestCase):
    TAG_COMMIT = "1" * 40
    TAG_OBJECT = "2" * 40
    TAG_TREE = "3" * 40
    SOURCE_DIGEST = "4" * 64
    RELEASE_ID = 2_468_013

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.candidate_root = self.root / "candidate-projections"
        self.receipt_root = self.root / "publication-receipts"
        self.verification_root = self.root / "publication-verification"
        self.raw_root = self.verification_root / "raw"
        self.download_root = self.verification_root / "downloads"
        self.worktree_root = self.root / "publication-worktrees"
        for path in (
            self.candidate_root,
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
        )
        for module, attribute, value in replacements:
            patcher = mock.patch.object(module, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.source = publication.SourceObservation(
            canonical_source_tree_sha256=self.SOURCE_DIGEST,
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

    def _source_inspector(
        self, *_args: object, **_kwargs: object
    ) -> publication.SourceObservation:
        return self.source

    def _pending_receipt(
        self,
        name: str,
        *,
        candidate_path: pathlib.Path | None = None,
    ) -> pathlib.Path:
        if candidate_path is None:
            candidate_path = self._candidate_projection(f"candidate-{name}")
        output, digest, source = publication.assemble_pending_receipt(
            candidate_path,
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
                    "contentType": "application/octet-stream",
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
            "isPrerelease": True,
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
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, RemoteFixtureRunner, AssetSinkRunner]:
        assets, manifest = self._asset_fixture()
        candidate = self._candidate_for_assets(f"candidate-{name}", assets)
        pending = self._pending_receipt(name, candidate_path=candidate)
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
                f"commit={self.TAG_COMMIT} assets=6\n"
            ).encode("ascii")

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
            source_environment={},
            git_tool="/usr/bin/git",
            gh_tool="/fixture/gh",
            source_inspector=self._source_inspector,
            deep_verifier=deep_verifier,
        )
        return output, raw, downloads, runner, sink

    def test_pending_receipt_is_exact_private_and_attempt_two_valid(self) -> None:
        candidate = self._candidate_projection("pending-exact-candidate")
        output = self._pending_receipt("pending-exact", candidate_path=candidate)

        receipt = json.loads(output.read_bytes())
        contract.validate_alpha3_publication_receipt(receipt)
        self.assertEqual(contract.PLATFORM_ALPHA3_STATUS_PENDING, receipt["status"])
        self.assertEqual(
            {"candidate_attestation", "observed_at", "source"},
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

    def test_cli_markers_identify_receipt_digest_for_both_states(self) -> None:
        output = self.root / "platform-alpha3-publication-receipt.json"

        pending_arguments = mock.Mock(
            command="pending",
            candidate_projection=self.root / "candidate.json",
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
                publication.PlatformAlpha3PublicationError,
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
            with self.assertRaises(publication.PlatformAlpha3PublicationError):
                publication._ensure_platform_safe_roots()

    def test_verified_transaction_uses_exact_bounded_commands_and_private_bytes(self) -> None:
        output, raw, downloads, runner, sink = self._collect_fixture("valid")

        receipt_bytes = output.read_bytes()
        receipt = json.loads(receipt_bytes)
        contract.validate_alpha3_publication_receipt(receipt)
        self.assertEqual(contract.PLATFORM_ALPHA3_STATUS_VERIFIED, receipt["status"])
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
        self.assertEqual(8, len(sink.calls))
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
                with self.assertRaises(publication.PlatformAlpha3PublicationError):
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
        with self.assertRaises(publication.PlatformAlpha3PublicationError):
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
            publication.PlatformAlpha3PublicationError,
            "raw bytes changed",
        ):
            publication._validate_raw_directory(raw, expected)

    def test_android_tool_drift_during_deep_verification_fails_closed(self) -> None:
        verified_before = set(self.receipt_root.glob("transaction.verified.*"))

        def mutate_tool() -> None:
            self.tools.llvm_nm.write_bytes(b"changed llvm-nm fixture\n")

        with self.assertRaisesRegex(
            publication.PlatformAlpha3PublicationError,
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

    def test_retryable_remote_failure_is_not_retried(self) -> None:
        assets, _manifest = self._asset_fixture()
        candidate = self._candidate_for_assets("candidate-retryable", assets)
        pending = self._pending_receipt("retryable", candidate_path=candidate)
        calls: list[tuple[str, ...]] = []

        def failed_runner(argv: Sequence[str], **_kwargs: object) -> BoundedResult:
            calls.append(tuple(argv))
            return BoundedResult(1)

        verified_before = set(self.receipt_root.glob("transaction.verified.*"))
        with self.assertRaisesRegex(
            publication.PlatformAlpha3PublicationRetryableError,
            r"^retryable:github-command-nonzero$",
        ):
            publication.collect_verified_receipt(
                pending,
                self.verifier,
                self.raw_root / "raw-retryable",
                self.download_root / "downloads-retryable",
                android_tools=self.tools,
                runner=failed_runner,
                source_environment={},
                git_tool="/usr/bin/git",
                gh_tool="/fixture/gh",
                source_inspector=self._source_inspector,
            )
        self.assertEqual(1, len(calls))
        self.assertEqual(
            verified_before,
            set(self.receipt_root.glob("transaction.verified.*")),
        )

    def test_generated_transactions_never_clobber_previous_receipts(self) -> None:
        candidate = self._candidate_projection("generated-transaction-candidate")
        first = self._pending_receipt("generated-first", candidate_path=candidate)
        first_bytes = first.read_bytes()
        second = self._pending_receipt("generated-second", candidate_path=candidate)

        self.assertNotEqual(first, second)
        self.assertEqual(first_bytes, first.read_bytes())
        self.assertTrue(second.is_file())

    def test_shared_atomic_writer_failure_leaves_no_partial_and_recovers(self) -> None:
        candidate = self._candidate_projection("atomic-failure-candidate")
        before = set(self.receipt_root.iterdir())
        with mock.patch.object(
            publication,
            "create_private_transaction_json",
            side_effect=publication.PublicationReceiptIOError(
                "injected atomic receipt failure"
            ),
        ):
            with self.assertRaisesRegex(
                publication.PlatformAlpha3PublicationError,
                "injected atomic receipt failure",
            ):
                publication.assemble_pending_receipt(
                    candidate,
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
            self.verifier,
            runner=lambda *_args, **_kwargs: BoundedResult(0),
            clock=QueueClock("2026-08-14T02:00:00Z"),
            source_environment={},
            git_tool="/usr/bin/git",
            source_inspector=self._source_inspector,
        )
        self.assertTrue(output.is_file())

        raw = self.raw_root / "raw-atomic-failure"
        publication._create_private_directory(
            raw,
            safe_root=self.raw_root,
            label="fixture raw transaction",
        )
        raw_leaf = publication.RAW_REPOSITORY_BEFORE_NAME
        with mock.patch.object(
            publication,
            "write_private_bytes_noreplace_at",
            side_effect=publication.PublicationReceiptIOError(
                "injected atomic raw failure"
            ),
        ):
            with self.assertRaisesRegex(
                publication.PlatformAlpha3PublicationError,
                "injected atomic raw failure",
            ):
                publication._write_raw(
                    raw,
                    raw_leaf,
                    b'{"visibility":"PUBLIC"}\n',
                    label="fixture raw evidence",
                )
        self.assertFalse((raw / raw_leaf).exists())
        self.assertEqual([], list(raw.glob(f".{raw_leaf}.pending-*")))
        publication._write_raw(
            raw,
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
                with self.assertRaises(publication.PlatformAlpha3PublicationError):
                    publication._inventory_fresh_downloads(directory, expected)

    def test_fixed_roots_reject_prefix_traversal_and_symlink_aliases(self) -> None:
        candidate = self._candidate_projection("safe-path-candidate")
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
                with self.assertRaises(publication.PlatformAlpha3PublicationError):
                    publication.assemble_pending_receipt(
                        unsafe,
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
                    f"commit={self.TAG_COMMIT} assets=6\n"
                ).encode("ascii"),
            )

        parsed, stdout = publication._run_deep_distribution_verifier(
            self.verifier,
            downloads,
            self.tools,
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
                "release fixture",
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
        environment = publication._process_environment({})

        observed = publication.inspect_verifier_source(
            self.verifier,
            git="/usr/bin/git",
            environment=environment,
            runner=capture_stdout,
        )

        self.assertEqual(observed.tag_commit, observed.verifier_commit)
        self.assertNotEqual(observed.tag_object, observed.tag_commit)
        self.assertRegex(observed.canonical_source_tree_sha256, r"^[0-9a-f]{64}$")
        source_file.write_text("dirty source\n", encoding="ascii")
        with self.assertRaisesRegex(
            publication.PlatformAlpha3PublicationError, "dirty"
        ):
            publication.inspect_verifier_source(
                self.verifier,
                git="/usr/bin/git",
                environment=environment,
                runner=capture_stdout,
            )


if __name__ == "__main__":
    unittest.main()
