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
    RELEASE_ID = 412_345_678
    TAG_OBJECT = "2" * 40
    TAG_COMMIT = "1" * 40
    OBSERVED_AT = dt.datetime(2026, 8, 14, 3, 0, 0, tzinfo=dt.UTC)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
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
        version: str = "0.1.0-alpha.3",
        kind: str = verification.COMPLETION_LEDGER_KIND,
        tag_commit: str | None = None,
    ) -> tuple[pathlib.Path, dict[str, str], str]:
        revision = "r1"
        tag = f"v{version}-{revision}"
        hashes = {
            asset: _digest(index)
            for index, asset in enumerate(verification.ASSET_NAMES, start=20)
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
            "source_commit": tag_commit or self.TAG_COMMIT,
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
        for index, name in enumerate(verification.ASSET_NAMES, start=1):
            assets.append(
                {
                    "apiUrl": (
                        f"{verification.API_ASSET_PREFIX}{500_000_000 + index}"
                    ),
                    "contentType": verification.ASSET_CONTENT_TYPES[name],
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
            "isPrerelease": True,
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
                for name in verification.ASSET_NAMES
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
        version: str = "0.1.0-alpha.3",
        kind: str = verification.COMPLETION_LEDGER_KIND,
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
        ledger, hashes, tag = self._ledger(name, version=version, kind=kind)
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
            source_environment={},
            git_tool="/fixture/git",
            gh_tool="/fixture/gh",
        )
        return raw, projection, runner, verify

    def test_alpha3_completion_collects_one_private_safe_transaction(self) -> None:
        raw, projection, runner, verify = self._collect("alpha3-valid")

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
        self.assertEqual(self.TAG_OBJECT, publication["source"]["tag_object"])
        self.assertEqual(self.TAG_COMMIT, publication["source"]["tag_commit"])
        self.assertEqual("2026-08-14T03:00:00Z", publication["observed_at"])
        self.assertEqual(list(verification.ASSET_NAMES), [a["name"] for a in document["assets"]])
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
            self.assertEqual(subprocess.DEVNULL, keyword_arguments["stderr"])
            if "cat-file" in arguments:
                command_kinds.append("git-type")
            elif "rev-parse" in arguments:
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
            "/fixture/gh",
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
            "/fixture/gh",
            "release",
            "view",
            "v0.1.0-alpha.3-r1",
            "--repo",
            verification.GH_REPOSITORY_ARGUMENT,
            "--json",
            ",".join(verification.RELEASE_VIEW_FIELDS),
        ]
        expected_verify = [
            "/fixture/gh",
            "release",
            "verify",
            "v0.1.0-alpha.3-r1",
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

    def test_publication_projection_directly_satisfies_pure_contract(self) -> None:
        distribution = apple_contract.frozen_alpha2_r1_distribution()
        tag = apple_contract.APPLE_ALPHA2_R1_IDENTITY["release_tag"]
        tag_object = "6fd8d410c078c50906dcaad885a4361e08702fc2"
        tag_commit = distribution["source_commit"]
        release_id = 355_454_389
        hashes = {
            verification.APPLE_DISTRIBUTION_NAME: distribution[
                "apple_distribution_evidence_sha256"
            ],
            verification.XCFRAMEWORK_ZIP_NAME: distribution["artifact_sha256"],
            verification.MANIFEST_NAME: distribution["manifest_sha256"],
            verification.SHA256SUMS_NAME: distribution["checksums_sha256"],
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
            source_environment={},
            git_tool="/fixture/git",
            gh_tool="/fixture/gh",
        )

        publication = json.loads(projection.read_text(encoding="ascii"))[
            "publication"
        ]
        apple_contract._validate_publication(
            publication,
            identity=dict(apple_contract.APPLE_ALPHA2_R1_IDENTITY),
            distribution=distribution,
            label="adapter cross-module fixture",
        )

    def test_release_view_identity_assets_and_types_fail_closed(self) -> None:
        mutations = (
            ("release-id", lambda value: value.__setitem__("databaseId", 7)),
            ("release-url", lambda value: value.__setitem__("url", "https://example.invalid")),
            ("draft", lambda value: value.__setitem__("isDraft", True)),
            ("asset-order", lambda value: value["assets"].reverse()),
            (
                "asset-hash",
                lambda value: value["assets"][0].__setitem__(
                    "digest", f"sha256:{'9' * 64}"
                ),
            ),
            ("asset-size-type", lambda value: value["assets"][0].__setitem__("size", True)),
            ("extra", lambda value: value.__setitem__("unexpected", None)),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                with self.assertRaises(verification.AppleReleaseVerificationError):
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
                    "tag", "v0.1.0-alpha.3-r2"
                ),
            ),
            (
                "hash",
                lambda value: value["public_assets_sha256"].__setitem__(
                    verification.ASSET_NAMES[0], "ABC"
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
                source_environment={},
                git_tool="/fixture/git",
                gh_tool="/fixture/gh",
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
                    source_environment={},
                    git_tool="/fixture/git",
                    gh_tool="/fixture/gh",
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
                source_environment={},
                git_tool="/fixture/git",
                gh_tool="/fixture/gh",
            )
        self.assertEqual([], runner.calls)

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
                        source_environment={},
                        git_tool="/fixture/git",
                        gh_tool="/fixture/gh",
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
                    source_environment={},
                    git_tool="/fixture/git",
                    gh_tool="/fixture/gh",
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
                    source_environment={},
                    git_tool="/fixture/git",
                    gh_tool="/fixture/gh",
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
                source_environment={},
                git_tool="/fixture/git",
                gh_tool="/fixture/gh",
            )
        self.assertEqual([], runner.calls)

        raw_two, projection_two = self._paths("git-env-policy")
        with self.assertRaisesRegex(
            verification.AppleReleaseVerificationError,
            "Git environment overrides",
        ):
            verification.collect_release_verification(
                ledger,
                str(self.RELEASE_ID),
                self.TAG_OBJECT,
                raw_two,
                projection_two,
                runner=runner,
                source_environment={"GIT_DIR": "/tmp/forged"},
                git_tool="/fixture/git",
                gh_tool="/fixture/gh",
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
                source_environment={},
                git_tool="/fixture/git",
                gh_tool="/fixture/gh",
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
                source_environment={},
                git_tool="/fixture/git",
                gh_tool="/fixture/gh",
            )
        self.assertTrue(raw.is_dir())
        self.assertEqual([], list(raw.iterdir()))
        self.assertFalse(projection.exists())


if __name__ == "__main__":
    unittest.main()
