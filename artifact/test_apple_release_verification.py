#!/usr/bin/env python3
"""Fail-closed tests for Apple GitHub release-verification I/O."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from typing import Any
from unittest import mock

import apple_release_verification as verification
import apple_publication_contract as apple_contract
from bounded_process import BoundedProcessError, BoundedResult
from git_provenance import GitProvenanceError


def _digest(index: int) -> str:
    return f"{index:064x}"


class FixtureRunner:
    def __init__(
        self,
        *,
        view_before: object,
        verify: object,
        view_after: object,
        tag_object: str,
        tag_commit: str,
        tag_object_after: str | None = None,
        repository_before: object | None = None,
        repository_after: object | None = None,
    ) -> None:
        self.view_before = view_before
        self.verify = verify
        self.view_after = view_after
        self.tag_object = tag_object
        self.tag_commit = tag_commit
        self.tag_object_after = tag_object_after or tag_object
        default_repository = {
            "nameWithOwner": verification.REPOSITORY,
            "url": verification.REPOSITORY_URL,
            "visibility": "PUBLIC",
        }
        self.repository_before = (
            default_repository if repository_before is None else repository_before
        )
        self.repository_after = (
            copy.deepcopy(default_repository)
            if repository_after is None
            else repository_after
        )
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.view_count = 0
        self.repository_view_count = 0
        self.tag_object_count = 0

    def __call__(self, argv: Any, **kwargs: object) -> BoundedResult:
        arguments = list(argv)
        self.calls.append((arguments, dict(kwargs)))
        if "cat-file" in arguments:
            return BoundedResult(0, b"tag\n")
        if "rev-parse" in arguments:
            if arguments[-1].endswith("^{commit}"):
                return BoundedResult(0, f"{self.tag_commit}\n".encode("ascii"))
            self.tag_object_count += 1
            value = (
                self.tag_object
                if self.tag_object_count == 1
                else self.tag_object_after
            )
            return BoundedResult(0, f"{value}\n".encode("ascii"))
        if "repo" in arguments and "view" in arguments:
            self.repository_view_count += 1
            value = (
                self.repository_before
                if self.repository_view_count == 1
                else self.repository_after
            )
            return BoundedResult(
                0, (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
            )
        if "release" in arguments and "view" in arguments:
            self.view_count += 1
            value = self.view_before if self.view_count == 1 else self.view_after
            return BoundedResult(
                0, (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
            )
        if "release" in arguments and "verify" in arguments:
            return BoundedResult(
                0, (json.dumps(self.verify, sort_keys=True) + "\n").encode("ascii")
            )
        raise AssertionError(f"unexpected fixture command: {arguments!r}")


class AppleReleaseVerificationTests(unittest.TestCase):
    def test_neutral_github_parser_is_the_single_policy_authority(self) -> None:
        shared = verification.github_release
        self.assertIs(verification.RELEASE_VIEW_FIELDS, shared.RELEASE_VIEW_FIELDS)
        self.assertIs(
            verification.REPOSITORY_VIEW_FIELDS,
            shared.REPOSITORY_VIEW_FIELDS,
        )
        for name in (
            "VERIFICATION_RESULT_MEDIA_TYPE",
            "STATEMENT_TYPE",
            "RELEASE_PREDICATE_TYPE",
            "RELEASE_CERTIFICATE_SAN",
            "RELEASE_CERTIFICATE_ISSUER",
            "TIMESTAMP_AUTHORITY_TYPE",
            "TIMESTAMP_AUTHORITY_URI",
        ):
            self.assertEqual(getattr(shared, name), getattr(verification, name))

    RELEASE_ID = 412_345_678
    TAG_OBJECT = "2" * 40
    TAG_COMMIT = "1" * 40
    SOURCE_PARENT_COMMIT = "0" * 40
    OBSERVED_AT = dt.datetime(2026, 8, 14, 3, 0, 0, tzinfo=dt.UTC)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.gh_tool = self.root / "gh"
        self.gh_tool.write_bytes(b"fixture GitHub CLI\n")
        os.chmod(self.gh_tool, 0o500)
        for attribute, value in (
            ("GITHUB_CLI_PATH", self.gh_tool),
            (
                "GITHUB_CLI_SHA256",
                hashlib.sha256(self.gh_tool.read_bytes()).hexdigest(),
            ),
        ):
            patcher = mock.patch.object(
                verification.github_release,
                attribute,
                value,
            )
            patcher.start()
            self.addCleanup(patcher.stop)
        self.fixture_environment = {"GH_TOKEN": "fixture_token_123456789"}
        self.ledger_root = self.root / "qperiapt-apple-release-worktrees"
        self.verification_root = self.root / "qperiapt-apple-release-verification"
        self.raw_root = self.verification_root / "raw"
        self.projection_root = self.verification_root / "projections"
        for path in (self.ledger_root, self.raw_root, self.projection_root):
            path.mkdir(parents=True, mode=0o700)
            os.chmod(path, 0o700)
        os.chmod(self.verification_root, 0o700)
        for attribute, value in (
            ("APPLE_LEDGER_ROOT", self.ledger_root),
            ("APPLE_VERIFICATION_ROOT", self.verification_root),
            ("APPLE_RAW_ROOT", self.raw_root),
            ("APPLE_PROJECTION_ROOT", self.projection_root),
        ):
            patcher = mock.patch.object(verification, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        provenance_patcher = mock.patch.object(
            verification,
            "require_direct_results_only_child",
        )
        self.require_direct_results_only_child = provenance_patcher.start()
        self.addCleanup(provenance_patcher.stop)

    def _private_directory(
        self,
        name: str,
        *,
        parent: pathlib.Path | None = None,
    ) -> pathlib.Path:
        path = (self.root if parent is None else parent) / name
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        return path

    def _ledger(
        self,
        name: str,
        *,
        version: str = "0.1.4",
        kind: str = verification.COMPLETION_LEDGER_KIND,
        source_commit: str | None = None,
    ) -> tuple[pathlib.Path, dict[str, str], str]:
        revision = "r1"
        is_historical = kind == verification.HISTORICAL_EXPECTATION_KIND
        tag = f"v{version}-{revision}" if is_historical else f"v{version}"
        hashes = {
            asset: _digest(index)
            for index, asset in enumerate(
                apple_contract.APPLE_PUBLIC_ASSET_NAMES,
                start=20,
            )
        }
        schema_version = 2 if kind == verification.COMPLETION_LEDGER_KIND else 1
        document = {
            "kind": kind,
            "public_assets_sha256": hashes,
            "release_identity": {
                "product_version": version,
                "revision": revision,
                "tag": tag,
            },
            "schema_version": schema_version,
            "source_commit": source_commit
            or (
                self.TAG_COMMIT
                if is_historical
                else self.SOURCE_PARENT_COMMIT
            ),
        }
        parent = self._private_directory(f"ledger-{name}", parent=self.ledger_root)
        path = parent / "asset-ledger.json"
        path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="ascii")
        os.chmod(path, 0o600)
        return path, hashes, tag

    def _view(
        self,
        *,
        tag: str,
        hashes: dict[str, str],
        release_id: int | None = None,
    ) -> dict[str, object]:
        assets = []
        for index, name in enumerate(
            apple_contract.APPLE_PUBLIC_ASSET_NAMES,
            start=1,
        ):
            assets.append(
                {
                    "apiUrl": (
                        f"{verification.API_ASSET_PREFIX}{500_000_000 + index}"
                    ),
                    "contentType": (
                        apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES[name]
                    ),
                    "createdAt": "2026-08-14T02:00:00Z",
                    "digest": f"sha256:{hashes[name]}",
                    "downloadCount": index,
                    "id": f"RA_fixture_{index}",
                    "label": "",
                    "name": name,
                    "size": 1_000 + index,
                    "state": "uploaded",
                    "updatedAt": "2026-08-14T02:01:00Z",
                    "url": (
                        f"{verification.RELEASE_DOWNLOAD_PREFIX}{tag}/{name}"
                    ),
                }
            )
        return {
            "assets": assets,
            "databaseId": release_id or self.RELEASE_ID,
            "isDraft": False,
            "isImmutable": True,
            "isPrerelease": "-" in tag,
            "publishedAt": "2026-08-14T02:02:00Z",
            "tagName": tag,
            "targetCommitish": "main",
            "url": f"{verification.RELEASE_URL_PREFIX}{tag}",
        }

    def _verify(
        self,
        *,
        tag: str,
        hashes: dict[str, str],
        tag_object: str | None = None,
        release_id: int | None = None,
    ) -> dict[str, object]:
        tag_object = tag_object or self.TAG_OBJECT
        release_id = release_id or self.RELEASE_ID
        purl = f"{verification.TAG_SUBJECT_PREFIX}{tag}"
        subjects = [
            {"digest": {"sha1": tag_object}, "uri": purl},
            *[
                {"digest": {"sha256": hashes[name]}, "name": name}
                for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES
            ],
        ]
        return {
            "attestation": {"private": "RAW_PII_SENTINEL"},
            "verificationResult": {
                "mediaType": verification.VERIFICATION_RESULT_MEDIA_TYPE,
                "signature": {
                    "certificate": {
                        "certificateIssuer": verification.RELEASE_CERTIFICATE_ISSUER,
                        "subjectAlternativeName": verification.RELEASE_CERTIFICATE_SAN,
                    }
                },
                "statement": {
                    "_type": verification.STATEMENT_TYPE,
                    "predicate": {
                        "databaseId": str(release_id),
                        "ownerId": "149552943",
                        "packageId": "1279236693",
                        "purl": purl,
                        "repository": verification.REPOSITORY,
                        "repositoryId": "1279236693",
                        "tag": tag,
                    },
                    "predicateType": verification.RELEASE_PREDICATE_TYPE,
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
                        "timestamp": "2026-08-14T02:02:01Z",
                        "type": verification.TIMESTAMP_AUTHORITY_TYPE,
                        "uri": verification.TIMESTAMP_AUTHORITY_URI,
                    }
                ],
            },
        }

    def _paths(self, name: str) -> tuple[pathlib.Path, pathlib.Path]:
        projection_parent = self._private_directory(
            f"projection-parent-{name}",
            parent=self.projection_root,
        )
        return (
            self.raw_root / f"raw-{name}",
            projection_parent / verification.PROJECTION_NAME,
        )

    def _collect(
        self,
        name: str,
        *,
        version: str = "0.1.4",
        kind: str = verification.COMPLETION_LEDGER_KIND,
        source_commit: str | None = None,
        mutate_view_before: Any = None,
        mutate_verify: Any = None,
        mutate_view_after: Any = None,
        mutate_repository_before: Any = None,
        mutate_repository_after: Any = None,
        tag_object_after: str | None = None,
    ) -> tuple[
        pathlib.Path,
        pathlib.Path,
        FixtureRunner,
        dict[str, object],
    ]:
        ledger, hashes, tag = self._ledger(
            name,
            version=version,
            kind=kind,
            source_commit=source_commit,
        )
        view_before = self._view(tag=tag, hashes=hashes)
        view_after = copy.deepcopy(view_before)
        verify = self._verify(tag=tag, hashes=hashes)
        repository_before = {
            "nameWithOwner": verification.REPOSITORY,
            "url": verification.REPOSITORY_URL,
            "visibility": "PUBLIC",
        }
        repository_after = copy.deepcopy(repository_before)
        if mutate_view_before is not None:
            mutate_view_before(view_before)
        if mutate_verify is not None:
            mutate_verify(verify)
        if mutate_view_after is not None:
            mutate_view_after(view_after)
        if mutate_repository_before is not None:
            mutate_repository_before(repository_before)
        if mutate_repository_after is not None:
            mutate_repository_after(repository_after)
        runner = FixtureRunner(
            view_before=view_before,
            verify=verify,
            view_after=view_after,
            tag_object=self.TAG_OBJECT,
            tag_commit=self.TAG_COMMIT,
            tag_object_after=tag_object_after,
            repository_before=repository_before,
            repository_after=repository_after,
        )
        raw, projection = self._paths(name)
        verification.collect_release_verification(
            ledger,
            str(self.RELEASE_ID),
            self.TAG_OBJECT,
            raw,
            projection,
            runner=runner,
            clock=lambda: self.OBSERVED_AT,
            source_environment=self.fixture_environment,
        )
        return raw, projection, runner, verify

    def test_stable_completion_collects_one_private_safe_transaction(self) -> None:
        raw, projection, runner, verify = self._collect("stable-valid")

        self.assertEqual(0o700, stat.S_IMODE(raw.stat().st_mode))
        self.assertEqual(verification.RAW_NAMES, {path.name for path in raw.iterdir()})
        for path in raw.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(1, path.stat().st_nlink)
        self.assertEqual(0o600, stat.S_IMODE(projection.stat().st_mode))
        document = json.loads(projection.read_text(encoding="ascii"))
        self.assertEqual(
            {
                "assets",
                "kind",
                "publication",
                "release_identity",
                "schema_version",
                "timestamp_authority",
            },
            set(document),
        )
        self.assertEqual(
            verification.REPOSITORY,
            document["release_identity"]["repository"],
        )
        self.assertEqual("PUBLIC", document["release_identity"]["visibility"])
        publication = document["publication"]
        self.assertEqual(self.RELEASE_ID, publication["release_id"])
        self.assertFalse(publication["prerelease"])
        self.assertEqual(self.TAG_OBJECT, publication["source"]["tag_object"])
        self.assertEqual(self.TAG_COMMIT, publication["source"]["tag_commit"])
        self.assertEqual("2026-08-14T03:00:00Z", publication["observed_at"])
        self.assertEqual(
            list(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
            [asset["name"] for asset in document["assets"]],
        )
        canonical_record = json.dumps(
            verify["verificationResult"],
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(canonical_record).hexdigest(),
            publication["release_attestation"]["verification_record_sha256"],
        )
        projection_text = projection.read_text(encoding="ascii")
        self.assertNotIn("RAW_PII_SENTINEL", projection_text)
        for forbidden in (
            "ownerId",
            "repositoryId",
            "packageId",
            "downloadCount",
            "apiUrl",
            str(raw),
        ):
            self.assertNotIn(forbidden, projection_text)

        command_kinds = []
        for arguments, keyword_arguments in runner.calls:
            if arguments[0] == verification.GIT:
                self.assertEqual(
                    subprocess.DEVNULL, keyword_arguments["stderr"]
                )
            else:
                stderr_sink = keyword_arguments["stderr"]
                self.assertIsInstance(stderr_sink, int)
                self.assertGreaterEqual(stderr_sink, 0)
            if "cat-file" in arguments:
                self.assertEqual(verification.GIT, arguments[0])
                self.assertNotIn(
                    "GH_TOKEN",
                    keyword_arguments["environment"],
                )
                command_kinds.append("git-type")
            elif "rev-parse" in arguments:
                self.assertEqual(verification.GIT, arguments[0])
                self.assertNotIn(
                    "GH_TOKEN",
                    keyword_arguments["environment"],
                )
                command_kinds.append(
                    "git-commit" if arguments[-1].endswith("^{commit}") else "git-tag"
                )
            elif "repo" in arguments:
                command_kinds.append("gh-repository-view")
            elif "view" in arguments:
                command_kinds.append("gh-view")
            else:
                command_kinds.append("gh-verify")
        self.assertEqual(
            [
                "git-type",
                "git-tag",
                "git-commit",
                "gh-repository-view",
                "gh-view",
                "gh-verify",
                "gh-view",
                "gh-repository-view",
                "git-type",
                "git-tag",
                "git-commit",
            ],
            command_kinds,
        )
        repository_calls = [
            (arguments, keyword_arguments)
            for arguments, keyword_arguments in runner.calls
            if "repo" in arguments and "view" in arguments
        ]
        expected_repository_view = [
            str(self.gh_tool),
            "repo",
            "view",
            verification.GH_REPOSITORY_ARGUMENT,
            "--json",
            ",".join(verification.REPOSITORY_VIEW_FIELDS),
        ]
        self.assertEqual(2, len(repository_calls))
        for arguments, keyword_arguments in repository_calls:
            self.assertEqual(expected_repository_view, arguments)
            self.assertEqual(
                verification.MAX_REPOSITORY_VIEW_BYTES,
                keyword_arguments["maximum_bytes"],
            )
        gh_calls = [
            (arguments, keyword_arguments)
            for arguments, keyword_arguments in runner.calls
            if "release" in arguments
        ]
        expected_view = [
            str(self.gh_tool),
            "release",
            "view",
            "v0.1.4",
            "--repo",
            verification.GH_REPOSITORY_ARGUMENT,
            "--json",
            ",".join(verification.RELEASE_VIEW_FIELDS),
        ]
        expected_verify = [
            str(self.gh_tool),
            "release",
            "verify",
            "v0.1.4",
            "--repo",
            verification.GH_REPOSITORY_ARGUMENT,
            "--format",
            "json",
        ]
        self.assertEqual(expected_view, gh_calls[0][0])
        self.assertEqual(expected_verify, gh_calls[1][0])
        self.assertEqual(expected_view, gh_calls[2][0])
        self.assertEqual(
            verification.MAX_RELEASE_VIEW_BYTES,
            gh_calls[0][1]["maximum_bytes"],
        )
        self.assertEqual(
            verification.MAX_RELEASE_VERIFY_BYTES,
            gh_calls[1][1]["maximum_bytes"],
        )
        self.assertEqual(
            [
                mock.call(
                    verification.REPOSITORY_ROOT,
                    self.SOURCE_PARENT_COMMIT,
                    self.TAG_COMMIT,
                ),
                mock.call(
                    verification.REPOSITORY_ROOT,
                    self.SOURCE_PARENT_COMMIT,
                    self.TAG_COMMIT,
                ),
            ],
            self.require_direct_results_only_child.call_args_list,
        )

    def test_github_environment_is_minimal_and_fails_closed(self) -> None:
        environment = verification._process_environment(
            self.fixture_environment
        )
        self.assertEqual(
            {
                "GH_NO_EXTENSION_UPDATE_NOTIFIER",
                "GH_NO_UPDATE_NOTIFIER",
                "GH_PAGER",
                "GH_PROMPT_DISABLED",
                "GH_TELEMETRY",
                "GH_TOKEN",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_NOSYSTEM",
                "GIT_CONFIG_SYSTEM",
                "GIT_NO_REPLACE_OBJECTS",
                "HOME",
                "LANG",
                "LC_ALL",
                "PAGER",
                "PATH",
                "TERM",
            },
            set(environment),
        )
        self.assertEqual("/usr/bin:/bin", environment["PATH"])
        self.assertNotIn("GH_TOKEN", verification._git_environment())
        for source, message in (
            ({}, "exactly one GitHub credential"),
            (
                {
                    "GH_TOKEN": "fixture_one_123456",
                    "GITHUB_TOKEN": "fixture_two_123456",
                },
                "exactly one GitHub credential",
            ),
            (
                {
                    **self.fixture_environment,
                    "HTTPS_PROXY": "https://proxy.invalid",
                },
                "network trust overrides",
            ),
            (
                {
                    **self.fixture_environment,
                    "SSL_CERT_FILE": "/fixture/ca.pem",
                },
                "network trust overrides",
            ),
            (
                {
                    **self.fixture_environment,
                    "GH_HOST": "example.invalid",
                },
                "network trust overrides",
            ),
        ):
            with self.subTest(source_keys=sorted(source)), self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                message,
            ):
                verification._process_environment(source)

    def test_fixed_bootstrap_observations_replace_ambient_gh_and_git(self) -> None:
        ledger, _hashes, tag = self._ledger("bootstrap")
        github_calls: list[tuple[list[str], dict[str, object]]] = []

        def github_runner(
            argv: list[str], **kwargs: object
        ) -> BoundedResult:
            github_calls.append((argv, kwargs))
            return BoundedResult(
                0,
                json.dumps({"databaseId": self.RELEASE_ID}).encode("ascii")
                + b"\n",
            )

        self.assertEqual(
            self.RELEASE_ID,
            verification.observe_release_id(
                ledger,
                runner=github_runner,
                source_environment=self.fixture_environment,
            ),
        )
        self.assertEqual(
            [
                str(self.gh_tool),
                "release",
                "view",
                tag,
                "--repo",
                verification.GH_REPOSITORY_ARGUMENT,
                "--json",
                "databaseId",
            ],
            github_calls[0][0],
        )
        stderr_sink = github_calls[0][1]["stderr"]
        self.assertIsInstance(stderr_sink, int)
        self.assertGreaterEqual(stderr_sink, 0)
        config_directory = pathlib.Path(
            github_calls[0][1]["environment"]["GH_CONFIG_DIR"]
        )
        self.assertFalse(config_directory.exists())

        git_outputs = iter((b"tag\n", f"{self.TAG_OBJECT}\n".encode("ascii")))
        git_calls: list[tuple[list[str], dict[str, object]]] = []

        def git_runner(argv: list[str], **kwargs: object) -> BoundedResult:
            git_calls.append((argv, kwargs))
            return BoundedResult(0, next(git_outputs))

        self.assertEqual(
            self.TAG_OBJECT,
            verification.observe_tag_object(
                ledger,
                runner=git_runner,
                source_environment={},
            ),
        )
        self.assertEqual(2, len(git_calls))
        for argv, kwargs in git_calls:
            self.assertEqual(verification.GIT, argv[0])
            self.assertNotIn("GH_TOKEN", kwargs["environment"])
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "Git environment overrides",
        ):
            verification.observe_tag_object(
                ledger,
                runner=git_runner,
                source_environment={"GIT_DIR": "/fixture/forged"},
            )

        def malformed_id_runner(
            _argv: list[str], **_kwargs: object
        ) -> BoundedResult:
            return BoundedResult(0, b'{"databaseId":true}\n')

        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "bounded positive integer",
        ):
            verification.observe_release_id(
                ledger,
                runner=malformed_id_runner,
                source_environment=self.fixture_environment,
            )

    def test_github_tool_requires_safe_canonical_bytes_and_resampling(self) -> None:
        identity = verification._gh_tool_identity()
        self.assertEqual(str(self.gh_tool), identity.path)
        verification._resample_gh_tool(identity)

        link = self.root / "gh-link"
        link.symlink_to(self.gh_tool)
        with (
            mock.patch.object(
                verification.github_release,
                "GITHUB_CLI_PATH",
                link,
            ),
            self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                "canonical|symlink",
            ),
        ):
            verification._gh_tool_identity()

        os.chmod(self.gh_tool, 0o700)
        self.gh_tool.write_bytes(b"mutated fixture GitHub CLI\n")
        os.chmod(self.gh_tool, 0o500)
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "identity or bytes changed",
        ):
            verification._resample_gh_tool(identity)

        os.chmod(self.gh_tool, 0o522)
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "metadata is unsafe",
        ):
            verification._gh_tool_identity()

    def test_alpha2_historical_expectation_uses_the_same_adapter(self) -> None:
        _, projection, _, _ = self._collect(
            "alpha2-valid",
            version="0.1.0-alpha.2",
            kind=verification.HISTORICAL_EXPECTATION_KIND,
        )
        document = json.loads(projection.read_text(encoding="ascii"))
        self.assertEqual(
            "v0.1.0-alpha.2-r1", document["release_identity"]["tag"]
        )
        self.assertEqual(4, len(document["assets"]))
        self.assertTrue(document["publication"]["prerelease"])
        self.require_direct_results_only_child.assert_not_called()

    def test_stable_tag_requires_a_direct_results_only_child(self) -> None:
        self.require_direct_results_only_child.side_effect = GitProvenanceError(
            "fixture topology differs"
        )
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "stable source/tag boundary",
        ):
            self._collect("stable-invalid-topology")
        self.assertFalse(
            (
                self.projection_root
                / "projection-parent-stable-invalid-topology"
                / verification.PROJECTION_NAME
            ).exists()
        )

        self.require_direct_results_only_child.reset_mock(side_effect=True)
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "must differ from its source parent",
        ):
            self._collect(
                "stable-source-equals-tag",
                source_commit=self.TAG_COMMIT,
            )
        self.require_direct_results_only_child.assert_not_called()

    def test_publication_projection_directly_satisfies_pure_contract(self) -> None:
        distribution = apple_contract.frozen_alpha2_r1_distribution()
        tag = apple_contract.APPLE_ALPHA2_R1_IDENTITY["release_tag"]
        tag_object = "6fd8d410c078c50906dcaad885a4361e08702fc2"
        tag_commit = distribution["source_commit"]
        release_id = 355_454_389
        hashes = {
            apple_contract.APPLE_DISTRIBUTION_ASSET_PATH: distribution[
                "apple_distribution_evidence_sha256"
            ],
            apple_contract.APPLE_XCFRAMEWORK_ARTIFACT_PATH: distribution[
                "artifact_sha256"
            ],
            apple_contract.APPLE_MANIFEST_ASSET_PATH: distribution[
                "manifest_sha256"
            ],
            apple_contract.APPLE_CHECKSUMS_ASSET_PATH: distribution[
                "checksums_sha256"
            ],
        }
        ledger_parent = self._private_directory(
            "alpha2-contract-ledger",
            parent=self.ledger_root,
        )
        ledger = ledger_parent / "asset-ledger.json"
        ledger.write_text(
            json.dumps(
                {
                    "kind": verification.HISTORICAL_EXPECTATION_KIND,
                    "public_assets_sha256": hashes,
                    "release_identity": {
                        "product_version": "0.1.0-alpha.2",
                        "revision": "r1",
                        "tag": tag,
                    },
                    "schema_version": 1,
                    "source_commit": tag_commit,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        os.chmod(ledger, 0o600)
        view = self._view(tag=tag, hashes=hashes, release_id=release_id)
        view["publishedAt"] = "2026-07-17T03:16:01Z"
        for asset in view["assets"]:
            asset["createdAt"] = "2026-07-17T03:15:17Z"
            asset["updatedAt"] = "2026-07-17T03:15:56Z"
        verify = self._verify(
            tag=tag,
            hashes=hashes,
            tag_object=tag_object,
            release_id=release_id,
        )
        verify["verificationResult"]["verifiedTimestamps"][0][
            "timestamp"
        ] = "2026-07-17T03:16:02Z"
        runner = FixtureRunner(
            view_before=view,
            verify=verify,
            view_after=copy.deepcopy(view),
            tag_object=tag_object,
            tag_commit=tag_commit,
        )
        raw, projection = self._paths("alpha2-contract")

        verification.collect_release_verification(
            ledger,
            str(release_id),
            tag_object,
            raw,
            projection,
            runner=runner,
            clock=lambda: dt.datetime(2026, 8, 14, 3, 0, 9, tzinfo=dt.UTC),
            source_environment=self.fixture_environment,
        )

        publication = json.loads(projection.read_text(encoding="ascii"))[
            "publication"
        ]
        apple_contract._validate_publication(
            publication,
            identity=dict(apple_contract.APPLE_ALPHA2_R1_IDENTITY),
            distribution=distribution,
            stable_source=None,
            expected_prerelease=True,
            label="adapter cross-module fixture",
        )

    def test_release_view_identity_assets_and_types_fail_closed(self) -> None:
        mutations = (
            ("release-id", lambda value: value.__setitem__("databaseId", 7)),
            ("release-url", lambda value: value.__setitem__("url", "https://example.invalid")),
            ("draft", lambda value: value.__setitem__("isDraft", True)),
            ("prerelease", lambda value: value.__setitem__("isPrerelease", True)),
            (
                "asset-order-swap",
                lambda value: value["assets"].__setitem__(
                    slice(0, 2), value["assets"][1::-1]
                ),
            ),
            (
                "asset-hash",
                lambda value: value["assets"][0].__setitem__(
                    "digest", f"sha256:{'9' * 64}"
                ),
            ),
            (
                "asset-content-type",
                lambda value: value["assets"][0].__setitem__(
                    "contentType", "application/octet-stream"
                ),
            ),
            ("asset-size-type", lambda value: value["assets"][0].__setitem__("size", True)),
            ("extra", lambda value: value.__setitem__("unexpected", None)),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                expected_failure = (
                    self.assertRaisesRegex(
                        verification.AppleReleaseVerificationError,
                        "GitHub Apple release view asset order differs",
                    )
                    if name == "asset-order-swap"
                    else self.assertRaises(
                        verification.AppleReleaseVerificationError
                    )
                )
                with expected_failure:
                    self._collect(f"view-{name}", mutate_view_before=mutation)
                projection = (
                    self.projection_root
                    / f"projection-parent-view-{name}"
                    / verification.PROJECTION_NAME
                )
                self.assertFalse(projection.exists())

    def test_release_attestation_policy_mutations_fail_closed(self) -> None:
        def result(value: dict[str, Any]) -> dict[str, Any]:
            return value["verificationResult"]

        mutations = (
            (
                "san",
                lambda value: result(value)["signature"]["certificate"].__setitem__(
                    "subjectAlternativeName", "https://example.invalid"
                ),
            ),
            (
                "predicate-type",
                lambda value: result(value)["statement"].__setitem__(
                    "predicateType", "https://example.invalid/predicate"
                ),
            ),
            (
                "timestamp-authority",
                lambda value: result(value)["verifiedTimestamps"][0].__setitem__(
                    "type", "Tlog"
                ),
            ),
            (
                "timestamps-count",
                lambda value: result(value)["verifiedTimestamps"].append(
                    copy.deepcopy(result(value)["verifiedTimestamps"][0])
                ),
            ),
            (
                "tag-subject",
                lambda value: result(value)["statement"]["subject"][0]["digest"].__setitem__(
                    "sha1", "9" * 40
                ),
            ),
            (
                "asset-subject",
                lambda value: result(value)["statement"]["subject"][1]["digest"].__setitem__(
                    "sha256", "9" * 64
                ),
            ),
            (
                "predicate-release-id",
                lambda value: result(value)["statement"]["predicate"].__setitem__(
                    "databaseId", "7"
                ),
            ),
            ("extra-result", lambda value: result(value).__setitem__("extra", None)),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                with self.assertRaises(verification.AppleReleaseVerificationError):
                    self._collect(f"verify-{name}", mutate_verify=mutation)
                projection = (
                    self.projection_root
                    / f"projection-parent-verify-{name}"
                    / verification.PROJECTION_NAME
                )
                self.assertFalse(projection.exists())

    def test_download_telemetry_drift_does_not_break_immutable_view(self) -> None:
        _, projection, _, _ = self._collect(
            "download-telemetry-drift",
            mutate_view_after=lambda value: value["assets"][0].__setitem__(
                "downloadCount", 99
            ),
        )
        self.assertTrue(projection.is_file())

    def test_security_relevant_release_view_and_local_tag_drift_fail_closed(
        self,
    ) -> None:
        mutations = (
            (
                "digest",
                lambda value: value["assets"][0].__setitem__(
                    "digest", f"sha256:{'9' * 64}"
                ),
            ),
            (
                "size",
                lambda value: value["assets"][0].__setitem__("size", 2_000),
            ),
            (
                "state",
                lambda value: value["assets"][0].__setitem__("state", "open"),
            ),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                with self.assertRaises(verification.AppleReleaseVerificationError):
                    self._collect(
                        f"remote-security-{name}",
                        mutate_view_after=mutation,
                    )
                self.assertFalse(
                    (
                        self.projection_root
                        / f"projection-parent-remote-security-{name}"
                        / verification.PROJECTION_NAME
                    ).exists()
                )

        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "annotated tag object differs",
        ):
            self._collect("local-toctou", tag_object_after="9" * 40)
        self.assertFalse(
            (
                self.projection_root
                / "projection-parent-local-toctou"
                / verification.PROJECTION_NAME
            ).exists()
        )

    def test_repository_visibility_is_public_exact_and_stable(self) -> None:
        mutations = (
            (
                "private",
                "before",
                lambda value: value.__setitem__("visibility", "PRIVATE"),
            ),
            (
                "internal",
                "before",
                lambda value: value.__setitem__("visibility", "INTERNAL"),
            ),
            (
                "type",
                "before",
                lambda value: value.__setitem__("visibility", True),
            ),
            (
                "identity",
                "before",
                lambda value: value.__setitem__(
                    "nameWithOwner", "billlza/other"
                ),
            ),
            (
                "pre-post-drift",
                "after",
                lambda value: value.__setitem__("visibility", "PRIVATE"),
            ),
        )
        for name, phase, mutation in mutations:
            with self.subTest(name=name):
                arguments = (
                    {"mutate_repository_before": mutation}
                    if phase == "before"
                    else {"mutate_repository_after": mutation}
                )
                with self.assertRaises(verification.AppleReleaseVerificationError):
                    self._collect(f"visibility-{name}", **arguments)
                self.assertFalse(
                    (
                        self.projection_root
                        / f"projection-parent-visibility-{name}"
                        / verification.PROJECTION_NAME
                    ).exists()
                )

    def test_ledger_discriminant_identity_and_hashes_are_strict(self) -> None:
        cases = (
            ("kind", lambda value: value.__setitem__("kind", "unknown")),
            ("schema", lambda value: value.__setitem__("schema_version", True)),
            (
                "identity",
                lambda value: value["release_identity"].__setitem__(
                    "tag", "v0.1.0-r2"
                ),
            ),
            (
                "hash",
                lambda value: value["public_assets_sha256"].__setitem__(
                    apple_contract.APPLE_PUBLIC_ASSET_NAMES[0], "ABC"
                ),
            ),
            ("extra", lambda value: value.__setitem__("unexpected", None)),
        )
        for name, mutation in cases:
            with self.subTest(name=name):
                ledger, _, _ = self._ledger(f"invalid-{name}")
                document = json.loads(ledger.read_text(encoding="ascii"))
                mutation(document)
                ledger.write_text(
                    json.dumps(document, sort_keys=True) + "\n", encoding="ascii"
                )
                os.chmod(ledger, 0o600)
                with self.assertRaises(verification.AppleReleaseVerificationError):
                    verification.load_release_expectation(ledger)

    def test_output_paths_are_private_absent_and_exclusive(self) -> None:
        ledger, hashes, tag = self._ledger("output-policy")
        view = self._view(tag=tag, hashes=hashes)
        verify = self._verify(tag=tag, hashes=hashes)
        runner = FixtureRunner(
            view_before=view,
            verify=verify,
            view_after=copy.deepcopy(view),
            tag_object=self.TAG_OBJECT,
            tag_commit=self.TAG_COMMIT,
        )
        raw, projection = self._paths("output-policy")
        projection.write_bytes(b"do not overwrite\n")
        os.chmod(projection, 0o600)
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError, "already exists"
        ):
            verification.collect_release_verification(
                ledger,
                str(self.RELEASE_ID),
                self.TAG_OBJECT,
                raw,
                projection,
                runner=runner,
                source_environment=self.fixture_environment,
            )
        self.assertEqual([], runner.calls)

        with mock.patch.object(
            verification,
            "APPLE_PROJECTION_ROOT",
            self.ledger_root,
        ):
            overlapping_projection = ledger.parent / verification.PROJECTION_NAME
            with self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                "must be disjoint",
            ):
                verification.collect_release_verification(
                    ledger,
                    str(self.RELEASE_ID),
                    self.TAG_OBJECT,
                    raw,
                    overlapping_projection,
                    runner=runner,
                    source_environment=self.fixture_environment,
                )
            self.assertFalse(overlapping_projection.exists())
        self.assertEqual([], runner.calls)

        self.assertEqual(b"do not overwrite\n", projection.read_bytes())
        self.assertFalse(raw.exists())

        broad_parent = self.projection_root / "broad-projection-parent"
        broad_parent.mkdir(mode=0o755)
        os.chmod(broad_parent, 0o755)
        with self.assertRaises(verification.AppleReleaseVerificationError):
            verification.collect_release_verification(
                ledger,
                str(self.RELEASE_ID),
                self.TAG_OBJECT,
                self.raw_root / "never-created-raw",
                broad_parent / verification.PROJECTION_NAME,
                runner=runner,
                source_environment=self.fixture_environment,
            )
        self.assertEqual([], runner.calls)

    def test_shared_atomic_raw_and_projection_writers_recover_without_partials(
        self,
    ) -> None:
        raw = self.raw_root / "raw-atomic-writer"
        raw.mkdir(mode=0o700)
        os.chmod(raw, 0o700)
        raw_name = verification.RAW_REPOSITORY_BEFORE_NAME
        projection_parent = self.projection_root / "projection-atomic-writer"
        projection_parent.mkdir(mode=0o700)
        os.chmod(projection_parent, 0o700)
        projection = projection_parent / verification.PROJECTION_NAME

        with mock.patch.object(
            verification,
            "write_private_bytes_noreplace_at",
            side_effect=verification.PublicationReceiptIOError(
                "injected shared atomic failure"
            ),
        ):
            with self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                "injected shared atomic failure",
            ):
                verification._write_raw_bytes(
                    raw,
                    raw_name,
                    b'{"visibility":"PUBLIC"}\n',
                    label="fixture Apple raw",
                )
            with self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                "injected shared atomic failure",
            ):
                verification._write_projection(
                    projection,
                    {"kind": "fixture", "schema_version": 1},
                )
        self.assertFalse((raw / raw_name).exists())
        self.assertFalse(projection.exists())
        self.assertEqual([], list(raw.glob(f".{raw_name}.pending-*")))
        self.assertEqual(
            [], list(projection_parent.glob(f".{verification.PROJECTION_NAME}.pending-*"))
        )

        verification._write_raw_bytes(
            raw,
            raw_name,
            b'{"visibility":"PUBLIC"}\n',
            label="fixture Apple raw",
        )
        projection_value = {"kind": "fixture", "schema_version": 1}
        digest = verification._write_projection(projection, projection_value)
        expected = (
            json.dumps(
                projection_value,
                indent=2,
                ensure_ascii=True,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        self.assertEqual(expected, projection.read_bytes())
        self.assertEqual(hashlib.sha256(expected).hexdigest(), digest)

    def test_fixed_roots_reject_tmp_prefix_traversal_and_symlink_escape(self) -> None:
        ledger, hashes, tag = self._ledger("fixed-root-policy")
        view = self._view(tag=tag, hashes=hashes)
        runner = FixtureRunner(
            view_before=view,
            verify=self._verify(tag=tag, hashes=hashes),
            view_after=copy.deepcopy(view),
            tag_object=self.TAG_OBJECT,
            tag_commit=self.TAG_COMMIT,
        )
        raw, projection = self._paths("fixed-root-policy")
        outside = self._private_directory("outside")
        outside_ledger = outside / "completed.json"
        outside_ledger.write_bytes(ledger.read_bytes())
        os.chmod(outside_ledger, 0o600)
        ledger_link = self.ledger_root / "ledger-link"
        ledger_link.symlink_to(outside_ledger)
        raw_link = self.raw_root / "raw-link"
        raw_link.symlink_to(outside, target_is_directory=True)
        projection_link = self.projection_root / "projection-link"
        projection_link.symlink_to(outside, target_is_directory=True)
        raw_evil_root = self.raw_root.parent / "raw-evil"
        raw_evil_root.mkdir(mode=0o700)

        cases = (
            (
                "tmp-ledger",
                pathlib.Path("/tmp/qperiapt-completed.json"),
                raw,
                projection,
            ),
            (
                "target-evil",
                ledger,
                raw_evil_root / "raw-output",
                projection,
            ),
            (
                "traversal",
                ledger,
                self.raw_root / "child" / ".." / ".." / "outside-raw",
                projection,
            ),
            ("ledger-symlink", ledger_link, raw, projection),
            ("raw-symlink", ledger, raw_link, projection),
            (
                "projection-symlink",
                ledger,
                raw,
                projection_link / verification.PROJECTION_NAME,
            ),
        )
        for name, selected_ledger, selected_raw, selected_projection in cases:
            with self.subTest(name=name):
                with self.assertRaises(verification.AppleReleaseVerificationError):
                    verification.collect_release_verification(
                        selected_ledger,
                        str(self.RELEASE_ID),
                        self.TAG_OBJECT,
                        selected_raw,
                        selected_projection,
                        runner=runner,
                        source_environment=self.fixture_environment,
                    )
                self.assertEqual([], runner.calls)
                self.assertFalse(selected_projection.exists())

        os.chmod(self.ledger_root, 0o755)
        try:
            with self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                "safe root is not an owned non-symlink directory",
            ):
                verification.collect_release_verification(
                    ledger,
                    str(self.RELEASE_ID),
                    self.TAG_OBJECT,
                    raw,
                    projection,
                    runner=runner,
                    source_environment=self.fixture_environment,
                )
        finally:
            os.chmod(self.ledger_root, 0o700)
        self.assertEqual([], runner.calls)

        os.chmod(self.verification_root, 0o755)
        try:
            with self.assertRaisesRegex(
                verification.AppleReleaseVerificationError,
                "safe root is not an owned non-symlink directory",
            ):
                verification.collect_release_verification(
                    ledger,
                    str(self.RELEASE_ID),
                    self.TAG_OBJECT,
                    raw,
                    projection,
                    runner=runner,
                    source_environment=self.fixture_environment,
                )
        finally:
            os.chmod(self.verification_root, 0o700)
        self.assertEqual([], runner.calls)
        self.assertFalse(raw.exists())
        self.assertFalse(projection.exists())

    def test_existing_raw_and_dangerous_git_environment_fail_before_commands(self) -> None:
        ledger, hashes, tag = self._ledger("preflight-policy")
        view = self._view(tag=tag, hashes=hashes)
        runner = FixtureRunner(
            view_before=view,
            verify=self._verify(tag=tag, hashes=hashes),
            view_after=copy.deepcopy(view),
            tag_object=self.TAG_OBJECT,
            tag_commit=self.TAG_COMMIT,
        )
        raw, projection = self._paths("preflight-policy")
        raw.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError, "already exists"
        ):
            verification.collect_release_verification(
                ledger,
                str(self.RELEASE_ID),
                self.TAG_OBJECT,
                raw,
                projection,
                runner=runner,
                source_environment=self.fixture_environment,
            )
        self.assertEqual([], runner.calls)

        raw_two, projection_two = self._paths("git-env-policy")
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "Git/GitHub/network trust overrides",
        ):
            verification.collect_release_verification(
                ledger,
                str(self.RELEASE_ID),
                self.TAG_OBJECT,
                raw_two,
                projection_two,
                runner=runner,
                source_environment={
                    **self.fixture_environment,
                    "GIT_DIR": "/tmp/forged",
                },
            )
        self.assertEqual([], runner.calls)
        self.assertFalse(raw_two.exists())

        raw_three, projection_three = self._paths("oversized-release-id")
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "bounded positive decimal",
        ):
            verification.collect_release_verification(
                ledger,
                "9" * 10_000,
                self.TAG_OBJECT,
                raw_three,
                projection_three,
                runner=runner,
                source_environment=self.fixture_environment,
            )
        self.assertEqual([], runner.calls)
        self.assertFalse(raw_three.exists())
        self.assertFalse(projection_three.exists())

    def test_bounded_command_failure_never_publishes_projection(self) -> None:
        ledger, _, _ = self._ledger("bounded-failure")
        raw, projection = self._paths("bounded-failure")

        def fail_runner(_argv: Any, **_kwargs: object) -> BoundedResult:
            raise BoundedProcessError("output_limit", "fixture overflow")

        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError, "failed safely"
        ):
            verification.collect_release_verification(
                ledger,
                str(self.RELEASE_ID),
                self.TAG_OBJECT,
                raw,
                projection,
                runner=fail_runner,
                source_environment=self.fixture_environment,
            )
        self.assertTrue(raw.is_dir())
        self.assertEqual([], list(raw.iterdir()))
        self.assertFalse(projection.exists())


if __name__ == "__main__":
    unittest.main()
