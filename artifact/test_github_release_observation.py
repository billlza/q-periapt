#!/usr/bin/env python3
"""Direct exact-policy tests for the neutral GitHub release parser."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from collections.abc import Callable
from typing import Any

import github_release_observation as observation


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True).encode("ascii") + b"\n"


class GitHubReleaseObservationTests(unittest.TestCase):
    REPOSITORY = "owner/product"
    REPOSITORY_URL = "https://github.com/owner/product"
    TAG = "v1.2.3-r1"
    TAG_COMMIT = "1" * 40
    TAG_OBJECT = "2" * 40
    RELEASE_ID = 12_345
    ASSET_NAMES = ("a.json", "b.zip")
    ASSET_BYTES = {"a.json": b'{"a":1}\n', "b.zip": b"zip fixture\n"}

    def policy(
        self,
        *,
        require_order: bool = True,
        expected_hashes: bool = True,
    ) -> observation.ReleasePolicy:
        hashes = (
            {
                name: hashlib.sha256(self.ASSET_BYTES[name]).hexdigest()
                for name in self.ASSET_NAMES
            }
            if expected_hashes
            else None
        )
        return observation.ReleasePolicy(
            repository=self.REPOSITORY,
            repository_url=self.REPOSITORY_URL,
            release_url=f"{self.REPOSITORY_URL}/releases/tag/{self.TAG}",
            download_prefix=f"{self.REPOSITORY_URL}/releases/download/",
            api_asset_prefix=(
                "https://api.github.com/repos/owner/product/releases/assets/"
            ),
            tag_subject_uri=f"pkg:github/{self.REPOSITORY}@{self.TAG}",
            tag=self.TAG,
            tag_commit=self.TAG_COMMIT,
            tag_object=self.TAG_OBJECT,
            asset_names=self.ASSET_NAMES,
            expected_release_id=self.RELEASE_ID,
            expected_sha256=hashes,
            expected_content_types={
                "a.json": "application/json",
                "b.zip": "application/zip",
            },
            require_asset_order=require_order,
        )

    def repository_view(self) -> dict[str, object]:
        return {
            "nameWithOwner": self.REPOSITORY,
            "url": self.REPOSITORY_URL,
            "visibility": "PUBLIC",
        }

    def release_view(self) -> dict[str, object]:
        assets = []
        for index, name in enumerate(self.ASSET_NAMES, start=1):
            assets.append(
                {
                    "apiUrl": (
                        "https://api.github.com/repos/owner/product/"
                        f"releases/assets/{100 + index}"
                    ),
                    "contentType": (
                        "application/json" if name.endswith(".json") else "application/zip"
                    ),
                    "createdAt": "2026-08-14T01:00:00Z",
                    "digest": (
                        "sha256:"
                        + hashlib.sha256(self.ASSET_BYTES[name]).hexdigest()
                    ),
                    "downloadCount": index,
                    "id": f"node_{index}",
                    "label": "",
                    "name": name,
                    "size": len(self.ASSET_BYTES[name]),
                    "state": "uploaded",
                    "updatedAt": "2026-08-14T01:30:00Z",
                    "url": (
                        f"{self.REPOSITORY_URL}/releases/download/"
                        f"{self.TAG}/{name}"
                    ),
                }
            )
        return {
            "assets": assets,
            "databaseId": self.RELEASE_ID,
            "isDraft": False,
            "isImmutable": True,
            "isPrerelease": True,
            "publishedAt": "2026-08-14T02:00:00Z",
            "tagName": self.TAG,
            "targetCommitish": "main",
            "url": f"{self.REPOSITORY_URL}/releases/tag/{self.TAG}",
        }

    def verification(self) -> dict[str, object]:
        policy = self.policy()
        return {
            "attestation": {"fixture": True},
            "verificationResult": {
                "mediaType": observation.VERIFICATION_RESULT_MEDIA_TYPE,
                "signature": {
                    "certificate": {
                        "certificateIssuer": observation.RELEASE_CERTIFICATE_ISSUER,
                        "subjectAlternativeName": observation.RELEASE_CERTIFICATE_SAN,
                    }
                },
                "statement": {
                    "_type": observation.STATEMENT_TYPE,
                    "predicate": {
                        "databaseId": str(self.RELEASE_ID),
                        "ownerId": "8",
                        "packageId": "9",
                        "purl": policy.tag_subject_uri,
                        "repository": self.REPOSITORY,
                        "repositoryId": "9",
                        "tag": self.TAG,
                    },
                    "predicateType": observation.RELEASE_PREDICATE_TYPE,
                    "subject": observation.expected_subjects(policy),
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
                        "type": observation.TIMESTAMP_AUTHORITY_TYPE,
                        "uri": observation.TIMESTAMP_AUTHORITY_URI,
                    }
                ],
            },
        }

    def assert_rejected(self, value: object, parser: Callable[[bytes], object]) -> None:
        with self.assertRaises(observation.GitHubReleaseObservationError):
            parser(_json(value))

    def test_exact_valid_repository_release_and_attestation(self) -> None:
        repository = observation.parse_repository_view(
            _json(self.repository_view()),
            policy=observation.RepositoryPolicy(
                repository=self.REPOSITORY,
                repository_url=self.REPOSITORY_URL,
            ),
        )
        release = observation.parse_release_view(
            _json(self.release_view()), policy=self.policy()
        )
        verification = observation.parse_release_verification(
            _json(self.verification()),
            policy=self.policy(),
            release_id=release.release_id,
            published_at=release.published_at,
        )

        self.assertTrue(repository.canonical)
        self.assertEqual(self.RELEASE_ID, release.release_id)
        self.assertEqual(list(self.ASSET_NAMES), [asset["name"] for asset in release.assets])
        self.assertEqual(
            observation.expected_subjects(self.policy()),
            verification.projection(include_verified_at=True)["subjects"],
        )
        self.assertEqual("2026-08-14T03:00:00Z", verification.verified_at)
        self.assertRegex(verification.verification_record_sha256, r"^[0-9a-f]{64}$")

    def test_repository_exact_keys_types_identity_and_duplicate_json(self) -> None:
        policy = observation.RepositoryPolicy(
            repository=self.REPOSITORY, repository_url=self.REPOSITORY_URL
        )
        parser = lambda data: observation.parse_repository_view(data, policy=policy)
        for name, mutate in (
            ("missing", lambda value: value.pop("url")),
            ("extra", lambda value: value.update(extra=None)),
            ("type", lambda value: value.update(visibility=True)),
            ("identity", lambda value: value.update(nameWithOwner="other/product")),
            ("private", lambda value: value.update(visibility="PRIVATE")),
        ):
            with self.subTest(name=name):
                value = self.repository_view()
                mutate(value)
                self.assert_rejected(value, parser)
        with self.assertRaises(observation.GitHubReleaseObservationError):
            parser(
                b'{"nameWithOwner":"owner/product","url":"one",'
                b'"url":"two","visibility":"PUBLIC"}\n'
            )

    def test_release_view_field_and_asset_mutations_fail_closed(self) -> None:
        parser = lambda data: observation.parse_release_view(
            data, policy=self.policy()
        )

        def asset(value: dict[str, Any]) -> dict[str, Any]:
            return value["assets"][0]

        cases: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
            ("missing", lambda value: value.pop("url")),
            ("extra", lambda value: value.update(extra=None)),
            ("bool-id", lambda value: value.update(databaseId=True)),
            ("draft", lambda value: value.update(isDraft=True)),
            ("mutable", lambda value: value.update(isImmutable=False)),
            ("not-prerelease", lambda value: value.update(isPrerelease=False)),
            ("tag", lambda value: value.update(tagName="other")),
            ("target", lambda value: value.update(targetCommitish="develop")),
            ("time", lambda value: value.update(publishedAt="2026-08-14 02:00:00Z")),
            ("order", lambda value: value["assets"].reverse()),
            ("duplicate-name", lambda value: asset(value).update(name="b.zip")),
            ("bool-size", lambda value: asset(value).update(size=True)),
            (
                "digest",
                lambda value: asset(value).update(
                    digest="sha256:" + "f" * 64
                ),
            ),
            ("state", lambda value: asset(value).update(state="new")),
            (
                "content-type",
                lambda value: asset(value).update(contentType="text/plain"),
            ),
            ("label", lambda value: asset(value).update(label="display")),
            (
                "download-url",
                lambda value: asset(value).update(
                    url="https://example.invalid"
                ),
            ),
            (
                "api-url",
                lambda value: asset(value).update(
                    apiUrl="https://example.invalid"
                ),
            ),
            ("node-id", lambda value: asset(value).update(id="unsafe/id")),
            (
                "created-after-published",
                lambda value: asset(value).update(
                    createdAt="2026-08-14T02:01:00Z"
                ),
            ),
            (
                "updated-before-created",
                lambda value: asset(value).update(
                    updatedAt="2026-08-14T00:59:00Z"
                ),
            ),
            (
                "bool-download-count",
                lambda value: asset(value).update(downloadCount=True),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                value: dict[str, Any] = copy.deepcopy(self.release_view())
                mutate(value)
                self.assert_rejected(value, parser)
        with self.assertRaises(observation.GitHubReleaseObservationError):
            parser(b'{"databaseId":12345,"databaseId":12346}\n')

    def test_release_view_can_canonicalize_exact_set_when_api_order_is_not_policy(
        self,
    ) -> None:
        value = self.release_view()
        value["assets"].reverse()
        parsed = observation.parse_release_view(
            _json(value), policy=self.policy(require_order=False)
        )
        self.assertEqual(
            list(self.ASSET_NAMES),
            [asset["name"] for asset in parsed.assets],
        )

    def test_attestation_subject_identity_time_and_shape_mutations_fail_closed(
        self,
    ) -> None:
        parser = lambda data: observation.parse_release_verification(
            data,
            policy=self.policy(),
            release_id=self.RELEASE_ID,
            published_at="2026-08-14T02:00:00Z",
        )

        def result(value: dict[str, Any]) -> dict[str, Any]:
            return value["verificationResult"]

        cases: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
            ("array-envelope", lambda value: value.update(attestation=[])),
            (
                "missing-result-field",
                lambda value: result(value).pop("signature"),
            ),
            ("extra-result", lambda value: result(value).update(extra=None)),
            ("media", lambda value: result(value).update(mediaType="other")),
            (
                "certificate-san",
                lambda value: result(value)["signature"]["certificate"].update(
                    subjectAlternativeName="other"
                ),
            ),
            (
                "verified-identity",
                lambda value: result(value)["verifiedIdentity"].update(
                    issuer={}
                ),
            ),
            (
                "timestamp-count",
                lambda value: result(value)["verifiedTimestamps"].append(
                    copy.deepcopy(result(value)["verifiedTimestamps"][0])
                ),
            ),
            (
                "timestamp-authority",
                lambda value: result(value)["verifiedTimestamps"][0].update(
                    uri="other"
                ),
            ),
            (
                "timestamp-before-publication",
                lambda value: result(value)["verifiedTimestamps"][0].update(
                    timestamp="2026-08-14T01:59:59Z"
                ),
            ),
            (
                "subject-order",
                lambda value: result(value)["statement"]["subject"].reverse(),
            ),
            (
                "asset-digest",
                lambda value: result(value)["statement"]["subject"][1][
                    "digest"
                ].update(sha256="f" * 64),
            ),
            (
                "tag-uri",
                lambda value: result(value)["statement"]["subject"][0].update(
                    uri="pkg:github/other"
                ),
            ),
            (
                "tag-digest",
                lambda value: result(value)["statement"]["subject"][0][
                    "digest"
                ].update(sha1="f" * 40),
            ),
            (
                "release-id",
                lambda value: result(value)["statement"]["predicate"].update(
                    databaseId="12346"
                ),
            ),
            (
                "repository-id",
                lambda value: result(value)["statement"]["predicate"].update(
                    repositoryId="0"
                ),
            ),
            (
                "predicate-extra",
                lambda value: result(value)["statement"]["predicate"].update(
                    extra=None
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                value: dict[str, Any] = copy.deepcopy(self.verification())
                mutate(value)
                self.assert_rejected(value, parser)
        self.assert_rejected([self.verification(), self.verification()], parser)
        duplicate = _json(self.verification()).replace(
            b'"mediaType":',
            b'"mediaType":"duplicate","mediaType":',
            1,
        )
        with self.assertRaises(observation.GitHubReleaseObservationError):
            parser(duplicate)


if __name__ == "__main__":
    unittest.main()
