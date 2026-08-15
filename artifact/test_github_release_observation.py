#!/usr/bin/env python3
"""Direct exact-policy tests for the neutral GitHub release parser."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import tempfile
import unittest
from collections.abc import Callable
from typing import Any
from unittest import mock

from bounded_process import BoundedProcessError, BoundedResult
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
        expected_prerelease: bool = True,
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
            expected_prerelease=expected_prerelease,
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

    @staticmethod
    def stable_tag_ruleset(
        *,
        ruleset_id: int = 42,
    ) -> dict[str, object]:
        return {
            "id": ruleset_id,
            "name": "stable tag immutability",
            "target": "tag",
            "source_type": "Repository",
            "source": observation.GITHUB_REPOSITORY,
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": list(observation.STABLE_TAG_REFS),
                    "exclude": [],
                }
            },
            "rules": [
                {
                    "type": "update",
                    "parameters": {
                        "update_allows_fetch_and_merge": False,
                    },
                },
                {"type": "deletion"},
            ],
        }

    @staticmethod
    def stable_tag_reference(reference: str, tag_object: str) -> dict[str, object]:
        api_root = (
            f"https://api.github.com/repos/{observation.GITHUB_REPOSITORY}/git"
        )
        return {
            "node_id": "fixture-ref-node",
            "object": {
                "sha": tag_object,
                "type": "tag",
                "url": f"{api_root}/tags/{tag_object}",
            },
            "ref": reference,
            "url": f"{api_root}/refs/{reference.removeprefix('refs/')}",
        }

    @staticmethod
    def stable_annotated_tag(
        reference: str,
        tag_object: str,
        commit: str,
    ) -> dict[str, object]:
        api_root = (
            f"https://api.github.com/repos/{observation.GITHUB_REPOSITORY}/git"
        )
        return {
            "message": "stable release",
            "node_id": "fixture-tag-node",
            "object": {
                "sha": commit,
                "type": "commit",
                "url": f"{api_root}/commits/{commit}",
            },
            "sha": tag_object,
            "tag": reference.removeprefix("refs/tags/"),
            "tagger": {
                "date": "2026-08-15T00:00:00Z",
                "email": "release@example.invalid",
                "name": "Release",
            },
            "url": f"{api_root}/tags/{tag_object}",
            "verification": {
                "payload": None,
                "reason": "unsigned",
                "signature": None,
                "verified": False,
                "verified_at": None,
            },
        }

    @staticmethod
    def stable_commit(commit: str, tree: str) -> dict[str, object]:
        api_root = (
            f"https://api.github.com/repos/{observation.GITHUB_REPOSITORY}/git"
        )
        return {
            "author": {},
            "committer": {},
            "html_url": "https://github.com/billlza/q-periapt/commit/" + commit,
            "message": "results-only release commit",
            "node_id": "fixture-commit-node",
            "parents": [],
            "sha": commit,
            "tree": {
                "sha": tree,
                "url": f"{api_root}/trees/{tree}",
            },
            "url": f"{api_root}/commits/{commit}",
            "verification": {},
        }

    def assert_rejected(self, value: object, parser: Callable[[bytes], object]) -> None:
        with self.assertRaises(observation.GitHubReleaseObservationError):
            parser(_json(value))

    def test_shared_github_cli_policy_pins_environment_capture_and_sink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)
            tool_digest = hashlib.sha256(tool_path.read_bytes()).hexdigest()
            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    tool_digest,
                ),
            ):
                tool = observation.select_github_cli()
                environment = observation.github_cli_environment(
                    {
                        "GH_TOKEN": "fixture_token_123456789",
                        "PATH": "/fixture/poisoned",
                    }
                )
                self.assertEqual("/usr/bin:/bin", environment["PATH"])

                capture_calls: list[tuple[list[str], dict[str, object]]] = []

                def capture_runner(
                    argv: list[str], **kwargs: object
                ) -> BoundedResult:
                    capture_calls.append((argv, kwargs))
                    return BoundedResult(0, b"{}\n")

                self.assertEqual(
                    b"{}\n",
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=environment,
                        label="fixture capture",
                        runner=capture_runner,
                    ),
                )
                self.assertEqual(
                    [tool.path, "repo", "view"],
                    capture_calls[0][0],
                )
                capture_environment = capture_calls[0][1]["environment"]
                self.assertEqual("0", capture_environment["GH_TELEMETRY"])
                config_directory = pathlib.Path(
                    capture_environment["GH_CONFIG_DIR"]
                )
                self.assertFalse(config_directory.exists())

                sink_calls: list[tuple[list[str], dict[str, object]]] = []

                def sink_runner(
                    argv: list[str], **kwargs: object
                ) -> BoundedResult:
                    sink_calls.append((argv, kwargs))
                    return BoundedResult(0)

                result = observation.write_github_cli_stdout_at(
                    tool,
                    ["release", "download"],
                    output_directory_fd=123,
                    output_name="asset.zip",
                    timeout_seconds=1,
                    maximum_bytes=1024,
                    environment=environment,
                    label="fixture sink",
                    runner=sink_runner,
                )
                self.assertEqual(0, result.returncode)
                self.assertEqual(
                    [tool.path, "release", "download"],
                    sink_calls[0][0],
                )
                self.assertEqual(
                    123,
                    sink_calls[0][1]["output_directory_fd"],
                )
                self.assertFalse(
                    pathlib.Path(
                        sink_calls[0][1]["environment"]["GH_CONFIG_DIR"]
                    ).exists()
                )

                hostile_environment = dict(environment)
                hostile_environment["HTTPS_PROXY"] = "https://proxy.invalid"
                with self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    "fixed minimal policy",
                ):
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=hostile_environment,
                        label="hostile environment",
                        runner=capture_runner,
                    )

                def mutating_runner(
                    _argv: list[str], **_kwargs: object
                ) -> BoundedResult:
                    os.chmod(tool_path, 0o700)
                    tool_path.write_bytes(b"mutated GitHub CLI\n")
                    os.chmod(tool_path, 0o500)
                    return BoundedResult(0, b"{}\n")

                with self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    "identity or bytes changed",
                ):
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=environment,
                        label="mutating tool",
                        runner=mutating_runner,
                    )

    def test_github_cli_rejects_configuration_written_during_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)
            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    hashlib.sha256(tool_path.read_bytes()).hexdigest(),
                ),
            ):
                tool = observation.select_github_cli()
                environment = observation.github_cli_environment(
                    {"GH_TOKEN": "fixture_token_123456789"}
                )
                observed_config: pathlib.Path | None = None

                def config_writer(
                    _argv: list[str], **kwargs: object
                ) -> BoundedResult:
                    nonlocal observed_config
                    command_environment = kwargs["environment"]
                    self.assertIsInstance(command_environment, dict)
                    observed_config = pathlib.Path(
                        command_environment["GH_CONFIG_DIR"]
                    )
                    (observed_config / "config.yml").write_text(
                        "http_unix_socket: /fixture/socket\n",
                        encoding="ascii",
                    )
                    return BoundedResult(0, b"{}\n")

                with self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    "configuration changed",
                ):
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=environment,
                        label="mutating configuration",
                        runner=config_writer,
                    )
                self.assertIsNotNone(observed_config)
                assert observed_config is not None
                self.assertFalse(observed_config.exists())

    def test_github_cli_source_environment_rejects_trust_overrides(self) -> None:
        for name in (
            "GIT_DIR",
            "GH_HOST",
            "GH_CONFIG_DIR",
            "GH_DEBUG",
            "HTTPS_PROXY",
            "SSL_CERT_FILE",
            "SSLKEYLOGFILE",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                observation.GitHubReleaseObservationError,
                "trust overrides",
            ):
                observation.github_cli_environment(
                    {
                        "GH_TOKEN": "fixture_token_123456789",
                        name: "/fixture/override",
                    }
                )

    def test_github_cli_execution_failures_are_typed_without_message_parsing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)
            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    hashlib.sha256(tool_path.read_bytes()).hexdigest(),
                ),
            ):
                tool = observation.select_github_cli()
                environment = observation.github_cli_environment(
                    {"GH_TOKEN": "fixture_token_123456789"}
                )

                def transport_failure(
                    _argv: list[str], **_kwargs: object
                ) -> BoundedResult:
                    raise BoundedProcessError("timeout", "fixture detail")

                with self.assertRaises(
                    observation.GitHubCliExecutionError
                ) as transport_context:
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=environment,
                        label="fixture transport",
                        runner=transport_failure,
                    )
                self.assertEqual("timeout", transport_context.exception.error_kind)
                self.assertIsNone(transport_context.exception.returncode)
                self.assertNotIn("fixture detail", str(transport_context.exception))

                def command_failure(
                    _argv: list[str], **_kwargs: object
                ) -> BoundedResult:
                    return BoundedResult(1, b"private output", b"private error")

                with self.assertRaises(
                    observation.GitHubCliExecutionError
                ) as command_context:
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=environment,
                        label="fixture command",
                        runner=command_failure,
                    )
                self.assertIsNone(command_context.exception.error_kind)
                self.assertEqual(1, command_context.exception.returncode)
                self.assertNotIn("private", str(command_context.exception))

                def malformed_result(
                    _argv: list[str], **_kwargs: object
                ) -> BoundedResult:
                    return BoundedResult(False, b"{}\n")

                with self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    "result type differs",
                ):
                    observation.capture_github_cli(
                        tool,
                        ["repo", "view"],
                        timeout_seconds=1,
                        maximum_bytes=1024,
                        environment=environment,
                        label="malformed result",
                        runner=malformed_result,
                    )

    def test_stable_tag_ruleset_parser_rejects_missing_bypass_and_target_drift(
        self,
    ) -> None:
        ruleset_list = _json([{"id": 42}])
        valid = self.stable_tag_ruleset()
        parsed = observation.parse_stable_tag_rulesets(
            ruleset_list,
            {42: _json(valid)},
        )
        self.assertEqual(observation.STABLE_TAG_REFS, parsed.tag_refs)
        self.assertEqual((42,), parsed.ruleset_ids)
        self.assertRegex(parsed.observation_sha256, r"^[0-9a-f]{64}$")

        cases: tuple[
            tuple[str, Callable[[dict[str, Any]], None], str], ...
        ] = (
            (
                "missing deletion",
                lambda value: value["rules"].pop(),
                "lack active no-bypass",
            ),
            (
                "bypass actor",
                lambda value: value.__setitem__(
                    "bypass_actors",
                    [
                        {
                            "actor_id": 1,
                            "actor_type": "User",
                            "bypass_mode": "always",
                        }
                    ],
                ),
                "permits bypass",
            ),
            (
                "wrong target",
                lambda value: value.__setitem__("target", "branch"),
                "target or enforcement",
            ),
            (
                "tag mismatch",
                lambda value: value["conditions"]["ref_name"].__setitem__(
                    "include", ["refs/tags/other"]
                ),
                "lack active no-bypass",
            ),
        )
        for label, mutate, message in cases:
            with self.subTest(label=label):
                invalid: dict[str, Any] = copy.deepcopy(valid)
                mutate(invalid)
                with self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    message,
                ):
                    observation.parse_stable_tag_rulesets(
                        ruleset_list,
                        {42: _json(invalid)},
                    )

        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "detail inventory",
        ):
            observation.parse_stable_tag_rulesets(ruleset_list, {})

    def test_stable_tag_protection_observer_uses_two_fixed_api_samples(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)
            ruleset_list = _json([{"id": 42}])
            detail = _json(self.stable_tag_ruleset())
            outputs = iter((ruleset_list, detail, ruleset_list, detail))
            calls: list[tuple[list[str], dict[str, object]]] = []

            def runner(argv: list[str], **kwargs: object) -> BoundedResult:
                calls.append((argv, kwargs))
                return BoundedResult(0, next(outputs))

            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    hashlib.sha256(tool_path.read_bytes()).hexdigest(),
                ),
            ):
                parsed = observation.observe_stable_tag_protection(
                    source_environment={"GH_TOKEN": "fixture_token_123456789"},
                    runner=runner,
                )
            self.assertEqual((42,), parsed.ruleset_ids)
            self.assertEqual(4, len(calls))
            for argv, kwargs in calls:
                self.assertEqual(str(tool_path), argv[0])
                self.assertEqual("api", argv[1])
                self.assertIn("GET", argv)
                self.assertIn(
                    f"X-GitHub-Api-Version: {observation.GITHUB_API_VERSION}",
                    argv,
                )
                self.assertFalse(
                    pathlib.Path(
                        kwargs["environment"]["GH_CONFIG_DIR"]
                    ).exists()
                )

    def test_stable_tag_state_parser_requires_exact_annotated_objects(self) -> None:
        commit = "3" * 40
        tree = "4" * 40
        tag_objects = ("5" * 40, "6" * 40)
        absent = {reference: _json([]) for reference in observation.STABLE_TAG_REFS}
        parsed_absent = observation.parse_stable_tag_state(absent, {}, None)
        self.assertEqual("absent", parsed_absent.state)
        self.assertIsNone(parsed_absent.commit)
        prefix_only = dict(absent)
        prefix_reference = observation.STABLE_TAG_REFS[0] + "-rc.1"
        prefix_only[observation.STABLE_TAG_REFS[0]] = _json(
            [self.stable_tag_reference(prefix_reference, "9" * 40)]
        )
        self.assertEqual(
            "absent",
            observation.parse_stable_tag_state(prefix_only, {}, None).state,
        )

        references = {
            reference: _json([self.stable_tag_reference(reference, tag_objects[index])])
            for index, reference in enumerate(observation.STABLE_TAG_REFS)
        }
        tags = {
            tag_object: _json(
                self.stable_annotated_tag(
                    observation.STABLE_TAG_REFS[index],
                    tag_object,
                    commit,
                )
            )
            for index, tag_object in enumerate(tag_objects)
        }
        commit_raw = _json(self.stable_commit(commit, tree))
        parsed = observation.parse_stable_tag_state(
            references,
            tags,
            commit_raw,
            expected_commit=commit,
            expected_tree=tree,
            expected_tag_objects=tag_objects,
        )
        self.assertEqual("exact", parsed.state)
        self.assertEqual(commit, parsed.commit)
        self.assertEqual(tree, parsed.tree)
        self.assertEqual(tag_objects, parsed.tag_objects)
        self.assertEqual(
            "exact",
            observation.parse_stable_tag_recovery_state(
                references,
                tags,
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            ).state,
        )

        apple_only_references = dict(absent)
        apple_only_references[observation.STABLE_TAG_REFS[0]] = references[
            observation.STABLE_TAG_REFS[0]
        ]
        apple_only = observation.parse_stable_tag_recovery_state(
            apple_only_references,
            {tag_objects[0]: tags[tag_objects[0]]},
            commit_raw,
            expected_commit=commit,
            expected_tree=tree,
            expected_tag_objects=tag_objects,
        )
        self.assertEqual("apple_only", apple_only.state)
        self.assertEqual((tag_objects[0],), apple_only.tag_objects)

        platform_only_references = dict(absent)
        platform_only_references[observation.STABLE_TAG_REFS[1]] = references[
            observation.STABLE_TAG_REFS[1]
        ]
        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "without its Apple predecessor",
        ):
            observation.parse_stable_tag_recovery_state(
                platform_only_references,
                {tag_objects[1]: tags[tag_objects[1]]},
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            )

        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "already exists",
        ):
            observation.parse_stable_tag_state(references, {}, None)

        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "reference differs",
        ):
            observation.parse_stable_tag_state(
                references,
                tags,
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tuple(reversed(tag_objects)),
            )

        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "objects are malformed",
        ):
            observation.parse_stable_tag_state(
                references,
                {tag_objects[0]: tags[tag_objects[0]]},
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=(tag_objects[0], tag_objects[0]),
            )

        wrong_reference_value = self.stable_tag_reference(
            observation.STABLE_TAG_REFS[0] + "-other",
            tag_objects[0],
        )
        wrong_reference = dict(references)
        wrong_reference[observation.STABLE_TAG_REFS[0]] = _json(
            [wrong_reference_value]
        )
        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "without its Apple predecessor",
        ):
            observation.parse_stable_tag_state(
                wrong_reference,
                tags,
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            )

        lightweight = copy.deepcopy(self.stable_tag_reference(
            observation.STABLE_TAG_REFS[0], tag_objects[0]
        ))
        lightweight["object"]["type"] = "commit"
        lightweight["object"]["sha"] = commit
        lightweight["object"]["url"] = (
            f"https://api.github.com/repos/{observation.GITHUB_REPOSITORY}"
            f"/git/commits/{commit}"
        )
        bad_references = dict(references)
        bad_references[observation.STABLE_TAG_REFS[0]] = _json([lightweight])
        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "not annotated",
        ):
            observation.parse_stable_tag_state(
                bad_references,
                tags,
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            )

        wrong_tag = copy.deepcopy(
            self.stable_annotated_tag(
                observation.STABLE_TAG_REFS[0], tag_objects[0], commit
            )
        )
        wrong_tag["object"]["sha"] = "7" * 40
        wrong_tags = dict(tags)
        wrong_tags[tag_objects[0]] = _json(wrong_tag)
        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "peeled commit differs",
        ):
            observation.parse_stable_tag_state(
                references,
                wrong_tags,
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            )

        wrong_name = copy.deepcopy(
            self.stable_annotated_tag(
                observation.STABLE_TAG_REFS[0], tag_objects[0], commit
            )
        )
        wrong_name["tag"] = "v0.1.0-other"
        wrong_name_tags = dict(tags)
        wrong_name_tags[tag_objects[0]] = _json(wrong_name)
        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "identity or peeled commit differs",
        ):
            observation.parse_stable_tag_state(
                references,
                wrong_name_tags,
                commit_raw,
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            )

        with self.assertRaisesRegex(
            observation.GitHubReleaseObservationError,
            "commit or tree differs",
        ):
            observation.parse_stable_tag_state(
                references,
                tags,
                _json(self.stable_commit(commit, "8" * 40)),
                expected_commit=commit,
                expected_tree=tree,
                expected_tag_objects=tag_objects,
            )

    def test_stable_tag_state_observer_uses_two_fixed_api_samples(self) -> None:
        commit = "3" * 40
        tree = "4" * 40
        tag_objects = ("5" * 40, "6" * 40)
        sample_outputs = []
        for _sample in range(2):
            sample_outputs.extend(
                _json([self.stable_tag_reference(reference, tag_objects[index])])
                for index, reference in enumerate(observation.STABLE_TAG_REFS)
            )
            sample_outputs.extend(
                _json(
                    self.stable_annotated_tag(
                        observation.STABLE_TAG_REFS[index],
                        tag_object,
                        commit,
                    )
                )
                for index, tag_object in enumerate(tag_objects)
            )
            sample_outputs.append(_json(self.stable_commit(commit, tree)))

        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)
            outputs = iter(sample_outputs)
            calls: list[list[str]] = []

            def runner(argv: list[str], **_kwargs: object) -> BoundedResult:
                calls.append(argv)
                return BoundedResult(0, next(outputs))

            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    hashlib.sha256(tool_path.read_bytes()).hexdigest(),
                ),
            ):
                parsed = observation.observe_stable_tag_state(
                    expected_commit=commit,
                    expected_tree=tree,
                    expected_tag_objects=tag_objects,
                    source_environment={"GH_TOKEN": "fixture_token_123456789"},
                    runner=runner,
                )
        self.assertEqual("exact", parsed.state)
        self.assertEqual(10, len(calls))
        self.assertEqual(4, sum("matching-refs" in argv[-1] for argv in calls))
        self.assertEqual(4, sum("/git/tags/" in argv[-1] for argv in calls))
        self.assertEqual(2, sum("/git/commits/" in argv[-1] for argv in calls))

    def test_stable_tag_state_observer_rejects_second_sample_tree_drift(self) -> None:
        commit = "3" * 40
        tree = "4" * 40
        tag_objects = ("5" * 40, "6" * 40)
        outputs: list[bytes] = []
        for sample_tree in (tree, "7" * 40):
            outputs.extend(
                _json([self.stable_tag_reference(reference, tag_objects[index])])
                for index, reference in enumerate(observation.STABLE_TAG_REFS)
            )
            outputs.extend(
                _json(
                    self.stable_annotated_tag(
                        observation.STABLE_TAG_REFS[index],
                        tag_object,
                        commit,
                    )
                )
                for index, tag_object in enumerate(tag_objects)
            )
            outputs.append(_json(self.stable_commit(commit, sample_tree)))

        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)
            remaining = iter(outputs)

            def runner(_argv: list[str], **_kwargs: object) -> BoundedResult:
                return BoundedResult(0, next(remaining))

            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    hashlib.sha256(tool_path.read_bytes()).hexdigest(),
                ),
            ):
                with self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    "commit or tree differs",
                ):
                    observation.observe_stable_tag_state(
                        expected_commit=commit,
                        expected_tree=tree,
                        expected_tag_objects=tag_objects,
                        source_environment={
                            "GH_TOKEN": "fixture_token_123456789"
                        },
                        runner=runner,
                    )

    def test_stable_tag_recovery_observer_rejects_state_drift(self) -> None:
        commit = "3" * 40
        tree = "4" * 40
        tag_objects = ("5" * 40, "6" * 40)
        absent = _json([])
        apple_reference = _json(
            [
                self.stable_tag_reference(
                    observation.STABLE_TAG_REFS[0], tag_objects[0]
                )
            ]
        )
        platform_reference = _json(
            [
                self.stable_tag_reference(
                    observation.STABLE_TAG_REFS[1], tag_objects[1]
                )
            ]
        )
        apple_tag = _json(
            self.stable_annotated_tag(
                observation.STABLE_TAG_REFS[0], tag_objects[0], commit
            )
        )
        platform_tag = _json(
            self.stable_annotated_tag(
                observation.STABLE_TAG_REFS[1], tag_objects[1], commit
            )
        )
        commit_raw = _json(self.stable_commit(commit, tree))
        outputs = iter(
            (
                apple_reference,
                absent,
                apple_tag,
                commit_raw,
                apple_reference,
                platform_reference,
                apple_tag,
                platform_tag,
                commit_raw,
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            tool_path = pathlib.Path(temporary).resolve() / "gh"
            tool_path.write_bytes(b"fixture GitHub CLI\n")
            os.chmod(tool_path, 0o500)

            def runner(_argv: list[str], **_kwargs: object) -> BoundedResult:
                return BoundedResult(0, next(outputs))

            with (
                mock.patch.object(observation, "GITHUB_CLI_PATH", tool_path),
                mock.patch.object(
                    observation,
                    "GITHUB_CLI_SHA256",
                    hashlib.sha256(tool_path.read_bytes()).hexdigest(),
                ),
                self.assertRaisesRegex(
                    observation.GitHubReleaseObservationError,
                    "changed during observation",
                ),
            ):
                observation.observe_stable_tag_recovery_state(
                    commit,
                    tree,
                    tag_objects,
                    source_environment={"GH_TOKEN": "fixture_token_123456789"},
                    runner=runner,
                )

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

    def test_release_class_is_an_explicit_bidirectional_policy(self) -> None:
        stable_view = self.release_view()
        stable_view["isPrerelease"] = False
        stable = observation.parse_release_view(
            _json(stable_view),
            policy=self.policy(expected_prerelease=False),
        )
        self.assertIn(b'"prerelease":false', stable.canonical)

        with self.assertRaises(observation.GitHubReleaseObservationError):
            observation.parse_release_view(
                _json(stable_view),
                policy=self.policy(expected_prerelease=True),
            )
        with self.assertRaises(observation.GitHubReleaseObservationError):
            observation.parse_release_view(
                _json(self.release_view()),
                policy=self.policy(expected_prerelease=False),
            )

    def test_release_class_policy_rejects_non_boolean_values(self) -> None:
        policy = self.policy()
        object.__setattr__(policy, "expected_prerelease", 1)
        with self.assertRaises(observation.GitHubReleaseObservationError):
            observation.parse_release_view(
                _json(self.release_view()), policy=policy
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
