#!/usr/bin/env python3
"""Fault-oriented tests for the sole coordinated stable GitHub publisher."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import tempfile
import unittest
from collections.abc import Mapping
from unittest import mock

import apple_publication_contract as apple_contract
import bounded_process
import github_release_observation as github_release
import platform_stable_publication_contract as platform_contract
import stable_github_publication as publication
from publication_receipt_io import canonical_json_bytes
from publication_receipt_io import PrivateDirectoryHandle, PublicationReceiptIOError


EXPECTED_ACTION_IDS = (
    "create-apple-draft",
    "create-platform-draft",
    "upload-apple-00-APPLE_DISTRIBUTION.json",
    "upload-apple-01-CQPeriapt.xcframework.zip",
    "upload-apple-02-MANIFEST.json",
    "upload-apple-03-SHA256SUMS",
    "upload-platform-00-PLATFORM_DISTRIBUTION.json",
    "upload-platform-01-SHA256SUMS",
    "upload-platform-02-q-periapt-android-0.1.4-16k-runtime-evidence.zip",
    "upload-platform-03-q-periapt-android-0.1.4-MANIFEST.json",
    "upload-platform-04-q-periapt-android-0.1.4.aar",
    "upload-platform-05-q-periapt-c-abi2-0.1.4-aarch64-unknown-linux-gnu.tar.gz",
    "upload-platform-06-q-periapt-c-abi2-0.1.4-x86_64-unknown-linux-gnu.tar.gz",
    "publish-apple",
    "publish-platform",
)


def _hex40(seed: int) -> str:
    return f"{seed:040x}"


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def fixture_plan() -> publication.PublicationPlan:
    tag_commit = _hex40(2)

    def release(
        domain: str,
        tag: str,
        tag_object: str,
        title: str,
        body: str,
        make_latest: bool,
        names: tuple[str, ...],
        content_types: object,
        seed: int,
    ) -> publication.ReleasePlan:
        assets = tuple(
            publication.AssetPlan(
                name=name,
                size=index + seed,
                sha256=_digest(bytes([seed + index]) * (index + seed)),
                content_type=content_types[name],
                staging_leaf=f"{domain}--{name}",
            )
            for index, name in enumerate(names)
        )
        create = publication._create_request_bytes(
            tag=tag,
            title=title,
            body=body,
            make_latest=make_latest,
            tag_commit=tag_commit,
        )
        publish = publication._publish_request_bytes(
            tag=tag,
            title=title,
            body=body,
            make_latest=make_latest,
            tag_commit=tag_commit,
        )
        return publication.ReleasePlan(
            domain=domain,
            tag=tag,
            tag_object=tag_object,
            title=title,
            body=body,
            make_latest=make_latest,
            assets=assets,
            create_request=publication._request_plan(
                f"create-{domain}.json", create
            ),
            publish_request=publication._request_plan(
                f"publish-{domain}.json", publish
            ),
        )

    plan = publication.PublicationPlan(
        results_sha256=_digest(b"pending results"),
        pending_commit=_hex40(4),
        source_parent_commit=_hex40(1),
        tag_commit=tag_commit,
        tag_tree=_hex40(3),
        canonical_source_tree_sha256=_digest(b"source tree"),
        platform_candidate_receipt_sha256=_digest(b"assembly receipt"),
        github_cli_sha256=github_release.GITHUB_CLI_SHA256,
        releases=(
            release(
                "apple",
                apple_contract.APPLE_V0_1_4_IDENTITY["release_tag"],
                _hex40(5),
                publication.APPLE_TITLE,
                publication.APPLE_BODY,
                True,
                apple_contract.APPLE_PUBLIC_ASSET_NAMES,
                apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES,
                11,
            ),
            release(
                "platform",
                platform_contract.RELEASE_TAG,
                _hex40(6),
                publication.PLATFORM_TITLE,
                publication.PLATFORM_BODY,
                False,
                platform_contract.PUBLIC_ASSET_NAMES,
                platform_contract.PUBLIC_ASSET_CONTENT_TYPES,
                31,
            ),
        ),
    )
    return publication.parse_plan(plan.document())


def _asset_view(asset: publication.AssetPlan, identity: int) -> github_release.MutableReleaseAsset:
    return github_release.MutableReleaseAsset(
        asset_id=identity,
        node_id=f"NODE_{identity}",
        name=asset.name,
        size=asset.size,
        sha256=asset.sha256,
        content_type=asset.content_type,
        state="uploaded",
        created_at="2026-08-15T00:00:00Z",
        updated_at="2026-08-15T00:00:01Z",
    )


def fixture_snapshot(
    plan: publication.PublicationPlan,
    index: int,
    *,
    apple_release_id: int = 101,
    platform_release_id: int = 202,
) -> publication.RemoteSnapshot:
    if index == 0:
        apple_count = -1
        platform_count = -1
    elif index == 1:
        apple_count = 0
        platform_count = -1
    elif index <= 2 + len(plan.apple.assets):
        apple_count = index - 2
        platform_count = 0
    else:
        apple_count = len(plan.apple.assets)
        platform_count = min(
            len(plan.platform.assets),
            index - 2 - len(plan.apple.assets),
        )
    apple_public = index >= publication.MAX_ACTIONS - 1
    platform_public = index == publication.MAX_ACTIONS

    def view(
        release: publication.ReleasePlan,
        release_id: int,
        count: int,
        public: bool,
        identity_base: int,
    ) -> github_release.MutableReleaseView | None:
        if count < 0:
            return None
        assets = tuple(
            _asset_view(asset, identity_base + asset_index)
            for asset_index, asset in enumerate(release.assets[:count])
        )
        stable = {
            "assets": [dataclasses.asdict(asset) for asset in assets],
            "body": release.body,
            "draft": not public,
            "immutable": public,
            "is_latest": public and release.domain == "apple",
            "prerelease": False,
            "published_at": "2026-08-15T00:01:00Z" if public else None,
            "release_id": release_id,
            "tag": release.tag,
            "target_commitish": plan.tag_commit,
            "title": release.title,
        }
        return github_release.MutableReleaseView(
            release_id=release_id,
            tag=release.tag,
            draft=not public,
            immutable=public,
            prerelease=False,
            is_latest=public and release.domain == "apple",
            published_at=stable["published_at"],
            assets=assets,
            canonical=canonical_json_bytes(stable),
        )

    apple = view(plan.apple, apple_release_id, apple_count, apple_public, 1_000)
    platform = view(
        plan.platform,
        platform_release_id,
        platform_count,
        platform_public,
        2_000,
    )
    repository_canonical = canonical_json_bytes(
        {
            "nameWithOwner": publication.REPOSITORY,
            "url": f"https://github.com/{publication.REPOSITORY}",
            "visibility": "PUBLIC",
        }
    )
    release_projection = {
        "repository_sha256": _digest(repository_canonical),
        "immutable_enabled": True,
        "immutable_enforced_by_owner": False,
        "latest_tag": plan.apple.tag if apple_public else None,
        "releases": [
            None if apple is None else json.loads(apple.canonical),
            None if platform is None else json.loads(platform.canonical),
        ],
    }
    observation = github_release.MutableReleaseTransactionObservation(
        repository_canonical=repository_canonical,
        immutable_enabled=True,
        immutable_enforced_by_owner=False,
        latest_tag=release_projection["latest_tag"],
        releases=(apple, platform),
        canonical=canonical_json_bytes(release_projection),
    )
    return publication.RemoteSnapshot(
        releases=observation,
        tag_protection_sha256=_digest(b"tag protection"),
        tag_state_sha256=_digest(b"tag state"),
    )


class FakeRemote:
    def __init__(
        self,
        plan: publication.PublicationPlan,
        journal_root: pathlib.Path | None = None,
    ) -> None:
        self.plan = plan
        self.journal_root = journal_root
        self.index = 0
        self.mutations: list[str] = []
        self.fail_before_effect = False
        self.fail_after_effect = False
        self.fail_next_observation = False

    def observe(self, _plan: publication.PublicationPlan) -> publication.RemoteSnapshot:
        if self.fail_next_observation:
            self.fail_next_observation = False
            raise github_release.GitHubCliExecutionError(
                "synthetic unavailable observation",
                error_kind="timeout",
                returncode=None,
            )
        return fixture_snapshot(self.plan, self.index)

    def mutate(
        self,
        _plan: publication.PublicationPlan,
        action: publication.MutationAction,
        _before: publication.RemoteSnapshot,
    ) -> None:
        if action.action_id != EXPECTED_ACTION_IDS[self.index]:
            raise AssertionError("mutation order differs from the independent oracle")
        if _before != fixture_snapshot(self.plan, self.index):
            raise AssertionError("mutation predecessor differs from the fake remote")
        if self.journal_root is not None:
            intent = self.journal_root / f"{self.index:06d}-intent.json"
            outcome = self.journal_root / f"{self.index:06d}-outcome.json"
            if not intent.is_file() or outcome.exists():
                raise AssertionError("mutation ran outside its durable intent window")
            value = json.loads(intent.read_bytes())
            if intent.read_bytes() != canonical_json_bytes(value):
                raise AssertionError("mutation intent bytes are not canonical")
        self.mutations.append(action.action_id)
        if self.fail_before_effect:
            self.fail_before_effect = False
            raise github_release.GitHubCliExecutionError(
                "synthetic mutation",
                error_kind="timeout",
                returncode=None,
            )
        self.index += 1
        if self.fail_after_effect:
            self.fail_after_effect = False
            raise github_release.GitHubCliExecutionError(
                "synthetic mutation",
                error_kind="timeout",
                returncode=None,
            )


class StableGitHubPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = fixture_plan()
        self.temporary = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.temporary.name).resolve()
        authority = base / "authority"
        publication_state = authority / "publication-state"
        self.root = publication_state / "github-stable-v0.1.4"
        for directory in (authority, publication_state, self.root):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        for name in (
            publication.STAGING_DIRECTORY,
            publication.REQUEST_DIRECTORY,
            publication.JOURNAL_DIRECTORY,
        ):
            child = self.root / name
            child.mkdir(mode=0o700)
            os.chmod(child, 0o700)
        for name in (
            publication.PREPARATION_INTENT_LEAF,
            publication.PLAN_LEAF,
        ):
            leaf = self.root / name
            leaf.write_bytes(canonical_json_bytes({"fixture": True}))
            os.chmod(leaf, 0o600)
        lock = self.root / publication.LOCK_LEAF
        lock.write_bytes(b"")
        os.chmod(lock, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @contextlib.contextmanager
    def publisher_patches(self):
        with (
            mock.patch.object(
                publication, "expected_state_root", return_value=self.root
            ),
            mock.patch.object(publication, "_registered_worktrees", return_value=()),
            mock.patch.object(
                publication, "_load_prepared_plan", return_value=self.plan
            ),
            mock.patch.object(publication, "verify_local_plan", return_value=None),
        ):
            yield

    def publish(self, remote: FakeRemote) -> publication.PublicationStatus:
        return publication.publish_plan(
            execute_real_github_mutation=True,
            expected_plan_sha256=self.plan.sha256(),
            expected_results_sha256=self.plan.results_sha256,
            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
            publication_order_ack=publication.ACK_PUBLICATION_ORDER,
            state_root=self.root,
            observer=remote.observe,
            mutator=remote.mutate,
        )

    def test_full_fake_remote_transaction_is_ordered_and_idempotent(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        with self.publisher_patches():
            status = self.publish(remote)
            repeated = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, status.applied_actions)
        self.assertEqual(
            list(EXPECTED_ACTION_IDS),
            remote.mutations,
        )
        self.assertTrue(repeated.complete)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))
        self.assertEqual(
            publication.MAX_ACTIONS * 3,
            len(list((self.root / publication.JOURNAL_DIRECTORY).iterdir())),
        )

    def test_unproven_exact_remote_prefixes_are_never_adopted(self) -> None:
        journal = self.root / publication.JOURNAL_DIRECTORY
        for remote_index in (1, 2, 6, 13, 14, 15):
            with self.subTest(remote_index=remote_index):
                for leaf in journal.iterdir():
                    leaf.unlink()
                remote = FakeRemote(self.plan, journal)
                remote.index = remote_index
                with self.publisher_patches():
                    with self.assertRaisesRegex(
                        publication.StableGitHubPublicationError,
                        "lacks same-plan journal provenance",
                    ):
                        self.publish(remote)
                self.assertEqual([], remote.mutations)
                self.assertEqual([], list(journal.iterdir()))

    def test_every_action_requires_a_fresh_exact_predecessor(self) -> None:
        journal = self.root / publication.JOURNAL_DIRECTORY
        remote = FakeRemote(self.plan, journal)
        observation_count = 0

        def observe_with_second_action_drift(
            plan: publication.PublicationPlan,
        ) -> publication.RemoteSnapshot:
            nonlocal observation_count
            observation_count += 1
            if observation_count == 4:
                return fixture_snapshot(plan, 2)
            return remote.observe(plan)

        with self.publisher_patches():
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError,
                "differs from the last journaled outcome",
            ):
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=observe_with_second_action_drift,
                    mutator=remote.mutate,
                )
        self.assertEqual(4, observation_count)
        self.assertEqual([EXPECTED_ACTION_IDS[0]], remote.mutations)
        self.assertTrue((journal / "000000-outcome.json").exists())
        self.assertFalse((journal / "000001-intent.json").exists())

    def test_all_sixteen_states_match_an_independent_order_oracle(self) -> None:
        expected_states = (
            (0, "both_absent"),
            (1, "apple_draft"),
            (2, "apple_prefix_0"),
            (3, "apple_prefix_1"),
            (4, "apple_prefix_2"),
            (5, "apple_prefix_3"),
            (6, "platform_prefix_0"),
            (7, "platform_prefix_1"),
            (8, "platform_prefix_2"),
            (9, "platform_prefix_3"),
            (10, "platform_prefix_4"),
            (11, "platform_prefix_5"),
            (12, "platform_prefix_6"),
            (13, "platform_prefix_7"),
            (14, "apple_published"),
            (15, "both_published"),
        )
        self.assertEqual(15, len(EXPECTED_ACTION_IDS))
        for index, expected_name in expected_states:
            state = publication.classify_remote_state(
                self.plan, fixture_snapshot(self.plan, index)
            )
            self.assertEqual(index, state.index)
            self.assertEqual(expected_name, state.name)

        platform_first_source = fixture_snapshot(self.plan, 2)
        platform_first = dataclasses.replace(
            platform_first_source,
            releases=dataclasses.replace(
                platform_first_source.releases,
                releases=(None, platform_first_source.releases.releases[1]),
            ),
        )
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "platform release exists before Apple",
        ):
            publication.classify_remote_state(self.plan, platform_first)

        apple_public_source = fixture_snapshot(self.plan, 14)
        apple_only_public = dataclasses.replace(
            apple_public_source,
            releases=dataclasses.replace(
                apple_public_source.releases,
                releases=(apple_public_source.releases.releases[0], None),
            ),
        )
        with self.assertRaises(publication.StableGitHubPublicationError):
            publication.classify_remote_state(self.plan, apple_only_public)

        for foreign_latest_index in (0, 1, 2, 3, 13, 14, 15):
            with self.subTest(foreign_latest_index=foreign_latest_index):
                source = fixture_snapshot(self.plan, foreign_latest_index)
                foreign_latest = dataclasses.replace(
                    source,
                    releases=dataclasses.replace(
                        source.releases,
                        latest_tag="foreign-stable",
                    ),
                )
                with self.assertRaises(
                    publication.StableGitHubPublicationError
                ):
                    publication.classify_remote_state(
                        self.plan,
                        foreign_latest,
                    )

    def test_all_actions_match_an_independent_literal_oracle(self) -> None:
        expected = (
            (0, "create-apple-draft", "create", "apple", None),
            (1, "create-platform-draft", "create", "platform", None),
            (
                2,
                "upload-apple-00-APPLE_DISTRIBUTION.json",
                "upload",
                "apple",
                0,
            ),
            (
                3,
                "upload-apple-01-CQPeriapt.xcframework.zip",
                "upload",
                "apple",
                1,
            ),
            (4, "upload-apple-02-MANIFEST.json", "upload", "apple", 2),
            (5, "upload-apple-03-SHA256SUMS", "upload", "apple", 3),
            (
                6,
                "upload-platform-00-PLATFORM_DISTRIBUTION.json",
                "upload",
                "platform",
                0,
            ),
            (
                7,
                "upload-platform-01-SHA256SUMS",
                "upload",
                "platform",
                1,
            ),
            (
                8,
                (
                    "upload-platform-02-q-periapt-android-0.1.4-"
                    "16k-runtime-evidence.zip"
                ),
                "upload",
                "platform",
                2,
            ),
            (
                9,
                "upload-platform-03-q-periapt-android-0.1.4-MANIFEST.json",
                "upload",
                "platform",
                3,
            ),
            (
                10,
                "upload-platform-04-q-periapt-android-0.1.4.aar",
                "upload",
                "platform",
                4,
            ),
            (
                11,
                (
                    "upload-platform-05-q-periapt-c-abi2-0.1.4-"
                    "aarch64-unknown-linux-gnu.tar.gz"
                ),
                "upload",
                "platform",
                5,
            ),
            (
                12,
                (
                    "upload-platform-06-q-periapt-c-abi2-0.1.4-"
                    "x86_64-unknown-linux-gnu.tar.gz"
                ),
                "upload",
                "platform",
                6,
            ),
            (13, "publish-apple", "publish", "apple", None),
            (14, "publish-platform", "publish", "platform", None),
        )
        actual = tuple(
            (
                action.index,
                action.action_id,
                action.kind,
                action.domain,
                action.asset_index,
            )
            for action in publication.action_sequence(self.plan)
        )
        self.assertEqual(expected, actual)

    def test_request_bodies_match_an_independent_canonical_oracle(self) -> None:
        apple_title = "Q-Periapt 0.1.4 Apple Distribution"
        apple_body = (
            "Stable ABI 2 Apple XCFramework distribution. Verify all four "
            "assets and the immutable release attestation before use."
        )
        platform_title = "Q-Periapt 0.1.4 ABI 2 Platform Distribution"
        platform_body = (
            "Stable ABI 2 Android and Linux distribution. Verify all seven "
            "assets and the immutable release attestation before use."
        )
        self.assertEqual(apple_title, publication.APPLE_TITLE)
        self.assertEqual(apple_body, publication.APPLE_BODY)
        self.assertEqual(platform_title, publication.PLATFORM_TITLE)
        self.assertEqual(platform_body, publication.PLATFORM_BODY)
        cases = (
            (
                self.plan.apple,
                "v0.1.4",
                apple_title,
                apple_body,
                "true",
            ),
            (
                self.plan.platform,
                "abi2-platforms-v0.1.4",
                platform_title,
                platform_body,
                "false",
            ),
        )
        for release, tag, title, body, make_latest in cases:
            self.assertEqual(tag, release.tag)
            self.assertEqual(title, release.title)
            self.assertEqual(body, release.body)
            create = canonical_json_bytes(
                {
                    "body": body,
                    "draft": True,
                    "generate_release_notes": False,
                    "make_latest": make_latest,
                    "name": title,
                    "prerelease": False,
                    "tag_name": tag,
                    "target_commitish": self.plan.tag_commit,
                }
            )
            publish = canonical_json_bytes(
                {
                    "body": body,
                    "draft": False,
                    "make_latest": make_latest,
                    "name": title,
                    "prerelease": False,
                    "tag_name": tag,
                    "target_commitish": self.plan.tag_commit,
                }
            )
            with self.subTest(domain=release.domain, request="create"):
                self.assertEqual(len(create), release.create_request.size)
                self.assertEqual(_digest(create), release.create_request.sha256)
            with self.subTest(domain=release.domain, request="publish"):
                self.assertEqual(len(publish), release.publish_request.size)
                self.assertEqual(_digest(publish), release.publish_request.sha256)

    def test_illegal_draft_prefix_and_publication_states_are_rejected(self) -> None:
        both_drafts = fixture_snapshot(self.plan, 2)
        apple_draft, platform_draft = both_drafts.releases.releases
        if apple_draft is None or platform_draft is None:
            self.fail("two-draft fixture is incomplete")
        draft_immutable = dataclasses.replace(apple_draft, immutable=True)
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "draft release claims immutability",
        ):
            publication.classify_remote_state(
                self.plan,
                dataclasses.replace(
                    both_drafts,
                    releases=dataclasses.replace(
                        both_drafts.releases,
                        releases=(draft_immutable, platform_draft),
                    ),
                ),
            )

        platform_public = dataclasses.replace(
            platform_draft,
            draft=False,
            immutable=True,
        )
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "platform was published before Apple",
        ):
            publication.classify_remote_state(
                self.plan,
                dataclasses.replace(
                    both_drafts,
                    releases=dataclasses.replace(
                        both_drafts.releases,
                        releases=(apple_draft, platform_public),
                    ),
                ),
            )

        apple_partial = fixture_snapshot(self.plan, 3)
        platform_started = fixture_snapshot(self.plan, 7)
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "platform assets exist before the Apple prefix",
        ):
            publication.classify_remote_state(
                self.plan,
                dataclasses.replace(
                    apple_partial,
                    releases=dataclasses.replace(
                        apple_partial.releases,
                        releases=(
                            apple_partial.releases.releases[0],
                            platform_started.releases.releases[1],
                        ),
                    ),
                ),
            )

        apple_complete = fixture_snapshot(self.plan, 6)
        complete_apple, empty_platform = apple_complete.releases.releases
        if complete_apple is None or empty_platform is None:
            self.fail("complete Apple draft fixture is incomplete")
        extra_apple = dataclasses.replace(
            complete_apple,
            assets=complete_apple.assets + (complete_apple.assets[-1],),
        )
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "Apple draft asset count differs",
        ):
            publication.classify_remote_state(
                self.plan,
                dataclasses.replace(
                    apple_complete,
                    releases=dataclasses.replace(
                        apple_complete.releases,
                        releases=(extra_apple, empty_platform),
                    ),
                ),
            )

    def test_composite_observer_is_exactly_two_single_sample_sandwiches(self) -> None:
        order: list[str] = []
        protection = github_release.StableTagProtectionObservation(
            repository=publication.REPOSITORY,
            ruleset_ids=(1,),
            tag_refs=github_release.STABLE_TAG_REFS,
            observation_sha256=_digest(b"tag protection"),
        )
        tag_state = github_release.StableTagStateObservation(
            repository=publication.REPOSITORY,
            state="exact",
            tag_refs=github_release.STABLE_TAG_REFS,
            tag_objects=(self.plan.apple.tag_object, self.plan.platform.tag_object),
            commit=self.plan.tag_commit,
            tree=self.plan.tag_tree,
            observation_sha256=_digest(b"tag state"),
        )

        def observe_protection(**_kwargs: object):
            order.append("P")
            return protection

        def observe_tag(**_kwargs: object):
            order.append("T")
            return tag_state

        def observe_release(*_args: object, **_kwargs: object):
            order.append("R")
            return fixture_snapshot(self.plan, 0).releases

        with (
            mock.patch.object(
                github_release,
                "sample_stable_tag_protection_once",
                side_effect=observe_protection,
            ),
            mock.patch.object(
                github_release,
                "sample_stable_tag_state_once",
                side_effect=observe_tag,
            ),
            mock.patch.object(
                github_release,
                "sample_mutable_release_transaction_once",
                side_effect=observe_release,
            ),
        ):
            observed = publication.observe_remote_transaction(self.plan)
        self.assertEqual(list("PTRTPPTRTP"), order)
        self.assertEqual(0, publication.classify_remote_state(self.plan, observed).index)

    def test_timeout_predecessor_keeps_one_unresolved_intent_and_never_retries(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        remote.fail_before_effect = True
        with self.publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self.publish(remote)
            self.assertEqual(1, len(remote.mutations))
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self.publish(remote)
        self.assertEqual(1, len(remote.mutations))
        journal = self.root / publication.JOURNAL_DIRECTORY
        self.assertTrue((journal / "000000-intent.json").exists())
        self.assertTrue((journal / "000000-reconciliation.json").exists())
        self.assertFalse((journal / "000000-outcome.json").exists())

    def test_nonzero_and_zero_predecessor_are_called_once_and_never_retried(self) -> None:
        for failure in ("nonzero", "zero"):
            with self.subTest(failure=failure):
                for leaf in (self.root / publication.JOURNAL_DIRECTORY).iterdir():
                    leaf.unlink()
                remote = FakeRemote(
                    self.plan, self.root / publication.JOURNAL_DIRECTORY
                )

                def retain_predecessor(
                    _plan: publication.PublicationPlan,
                    action: publication.MutationAction,
                    _before: publication.RemoteSnapshot,
                ) -> None:
                    remote.mutations.append(action.action_id)
                    if failure == "nonzero":
                        raise github_release.GitHubCliExecutionError(
                            "synthetic nonzero",
                            error_kind=None,
                            returncode=1,
                        )

                with self.publisher_patches():
                    with self.assertRaises(
                        publication.StableGitHubPublicationOutcomeUnknown
                    ):
                        publication.publish_plan(
                            execute_real_github_mutation=True,
                            expected_plan_sha256=self.plan.sha256(),
                            expected_results_sha256=self.plan.results_sha256,
                            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                            publication_order_ack=(
                                publication.ACK_PUBLICATION_ORDER
                            ),
                            state_root=self.root,
                            observer=remote.observe,
                            mutator=retain_predecessor,
                        )
                    with self.assertRaises(
                        publication.StableGitHubPublicationOutcomeUnknown
                    ):
                        self.publish(remote)
                self.assertEqual(1, len(remote.mutations))
                journal = self.root / publication.JOURNAL_DIRECTORY
                self.assertTrue(
                    (journal / "000000-reconciliation.json").exists()
                )
                self.assertFalse((journal / "000000-outcome.json").exists())

    def test_local_integrity_effect_is_manual_only_across_restart(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )

        def mutate_then_lose_local_integrity(
            plan: publication.PublicationPlan,
            action: publication.MutationAction,
            before: publication.RemoteSnapshot,
        ) -> None:
            remote.mutate(plan, action, before)
            raise github_release.GitHubMutationInputIntegrityError(
                "synthetic local input integrity failure",
                preceding_type="BoundedProcessError",
                error_kind="timeout",
                returncode=None,
                signal_number=None,
                cleanup_ambiguous=False,
            )

        with self.publisher_patches():
            with self.assertRaises(
                publication.StableGitHubPublicationBoundaryIntegrityError
            ) as caught:
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=remote.observe,
                    mutator=mutate_then_lose_local_integrity,
                )
            self.assertEqual("timeout", caught.exception.error_kind)
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationOutcomeUnknown,
                "manual review",
            ):
                self.publish(remote)
            status = publication.status_plan(
                state_root=self.root,
                observer=remote.observe,
            )
        journal = self.root / publication.JOURNAL_DIRECTORY
        self.assertTrue((journal / "000000-intent.json").exists())
        self.assertFalse((journal / "000000-reconciliation.json").exists())
        self.assertFalse((journal / "000000-outcome.json").exists())
        self.assertEqual(1, len(remote.mutations))
        self.assertTrue(status.unresolved_intent)
        self.assertTrue(status.manual_review_required)
        self.assertFalse(status.reconciliation_eligible)

    def test_signal_and_reap_input_integrity_are_boundary_primary(self) -> None:
        cases = (
            (None, 15, False),
            ("reap", 15, True),
        )
        for error_kind, signal_number, cleanup_ambiguous in cases:
            with self.subTest(
                error_kind=error_kind,
                cleanup_ambiguous=cleanup_ambiguous,
            ):
                for leaf in (self.root / publication.JOURNAL_DIRECTORY).iterdir():
                    leaf.unlink()
                remote = FakeRemote(
                    self.plan, self.root / publication.JOURNAL_DIRECTORY
                )

                def mutate_then_fail_local(
                    plan: publication.PublicationPlan,
                    action: publication.MutationAction,
                    before: publication.RemoteSnapshot,
                ) -> None:
                    remote.mutate(plan, action, before)
                    raise github_release.GitHubMutationInputIntegrityError(
                        "synthetic combined local integrity failure",
                        preceding_type="SystemExit",
                        error_kind=error_kind,
                        returncode=None,
                        signal_number=signal_number,
                        cleanup_ambiguous=cleanup_ambiguous,
                    )

                with self.publisher_patches():
                    with self.assertRaises(
                        publication.StableGitHubPublicationBoundaryIntegrityError
                    ) as caught:
                        publication.publish_plan(
                            execute_real_github_mutation=True,
                            expected_plan_sha256=self.plan.sha256(),
                            expected_results_sha256=self.plan.results_sha256,
                            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                            publication_order_ack=(
                                publication.ACK_PUBLICATION_ORDER
                            ),
                            state_root=self.root,
                            observer=remote.observe,
                            mutator=mutate_then_fail_local,
                        )
                    self.assertEqual(error_kind, caught.exception.error_kind)
                    self.assertEqual(
                        signal_number,
                        caught.exception.signal_number,
                    )
                    self.assertEqual(
                        cleanup_ambiguous,
                        caught.exception.cleanup_ambiguous,
                    )
                    with self.assertRaisesRegex(
                        publication.StableGitHubPublicationOutcomeUnknown,
                        "manual review",
                    ):
                        self.publish(remote)
                self.assertEqual(1, len(remote.mutations))
                journal = self.root / publication.JOURNAL_DIRECTORY
                self.assertTrue((journal / "000000-intent.json").exists())
                self.assertFalse(
                    (journal / "000000-reconciliation.json").exists()
                )

    def test_bounded_signal_input_drift_reaches_coordinator_boundary(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        base = pathlib.Path(self.temporary.name).resolve()
        tool_path = base / "fixture-gh"
        tool_path.write_bytes(b"fixture GitHub CLI\n")
        os.chmod(tool_path, 0o500)
        body = b"fixed request body\n"
        body_path = base / "fixture-request"
        body_path.write_bytes(body)
        os.chmod(body_path, 0o600)
        mutation_calls = 0

        def mutate_with_signal_and_input_drift(
            _plan: publication.PublicationPlan,
            _action: publication.MutationAction,
            _before: publication.RemoteSnapshot,
        ) -> None:
            nonlocal mutation_calls
            mutation_calls += 1
            descriptor = os.open(body_path, os.O_RDWR)

            def drift_then_signal(
                _argv: list[str], **kwargs: object
            ) -> bounded_process.BoundedResult:
                input_fd = kwargs["stdin_fd"]
                if type(input_fd) is not int:
                    self.fail("GitHub mutation runner did not receive an input fd")
                os.pwrite(input_fd, b"X", 0)
                raise bounded_process._TerminationSignal(15)

            try:
                tool = github_release.select_github_cli()
                environment = github_release.github_cli_environment(
                    {"GH_TOKEN": "fixture_token_123456789"}
                )
                github_release.execute_github_api_json_mutation(
                    tool,
                    method="POST",
                    endpoint=f"/repos/{publication.REPOSITORY}/releases",
                    input_fd=descriptor,
                    input_size=len(body),
                    input_sha256=_digest(body),
                    timeout_seconds=publication.JSON_MUTATION_TIMEOUT_SECONDS,
                    maximum_bytes=publication.MAX_MUTATION_OUTPUT_BYTES,
                    environment=environment,
                    label="fixture coordinator signal mutation",
                    runner=drift_then_signal,
                )
            finally:
                os.close(descriptor)

        with (
            self.publisher_patches(),
            mock.patch.object(github_release, "GITHUB_CLI_PATH", tool_path),
            mock.patch.object(
                github_release,
                "GITHUB_CLI_SHA256",
                _digest(tool_path.read_bytes()),
            ),
        ):
            with self.assertRaises(
                publication.StableGitHubPublicationBoundaryIntegrityError
            ) as caught:
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=remote.observe,
                    mutator=mutate_with_signal_and_input_drift,
                )
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationOutcomeUnknown,
                "manual review",
            ):
                self.publish(remote)
        self.assertEqual(1, mutation_calls)
        self.assertEqual(15, caught.exception.signal_number)
        self.assertFalse(caught.exception.cleanup_ambiguous)
        journal = self.root / publication.JOURNAL_DIRECTORY
        self.assertTrue((journal / "000000-intent.json").exists())
        self.assertFalse((journal / "000000-reconciliation.json").exists())
        self.assertFalse((journal / "000000-outcome.json").exists())

    def test_cli_failure_plus_lock_drift_preserves_sanitized_execution_kind(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )

        def fail_and_unlink_lock(
            _plan: publication.PublicationPlan,
            action: publication.MutationAction,
            before: publication.RemoteSnapshot,
        ) -> None:
            self.assertEqual(0, action.index)
            self.assertEqual(0, publication.classify_remote_state(
                self.plan, before
            ).index)
            remote.mutations.append(action.action_id)
            (self.root / publication.LOCK_LEAF).unlink()
            raise github_release.GitHubCliExecutionError(
                "synthetic mutation",
                error_kind="timeout",
                returncode=None,
            )

        with self.publisher_patches():
            with self.assertRaises(
                publication.StableGitHubPublicationBoundaryIntegrityError
            ) as caught:
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=remote.observe,
                    mutator=fail_and_unlink_lock,
                )
        self.assertEqual("timeout", caught.exception.error_kind)
        self.assertIsNone(caught.exception.returncode)
        journal = self.root / publication.JOURNAL_DIRECTORY
        self.assertTrue((journal / "000000-intent.json").exists())
        self.assertFalse((journal / "000000-reconciliation.json").exists())
        self.assertFalse((journal / "000000-outcome.json").exists())
        self.assertEqual(1, len(remote.mutations))

    def test_unlinked_held_lock_blocks_all_entrypoints_without_remote_calls(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        observations = 0

        def observe(plan: publication.PublicationPlan) -> publication.RemoteSnapshot:
            nonlocal observations
            observations += 1
            return remote.observe(plan)

        with self.publisher_patches(), mock.patch.object(
            publication,
            "build_plan_from_pending_results",
            side_effect=AssertionError("split prepare reached source loading"),
        ) as build:
            with self.assertRaises(
                publication.StableGitHubPublicationBoundaryIntegrityError
            ):
                with publication.publication_lock(
                    self.root,
                    allow_create=False,
                ):
                    (self.root / publication.LOCK_LEAF).unlink()
                    with self.assertRaises(
                        publication.StableGitHubPublicationBoundaryIntegrityError
                    ):
                        publication.prepare_plan(
                            self.plan.results_sha256,
                            state_root=self.root,
                        )
                    with self.assertRaises(
                        publication.StableGitHubPublicationBoundaryIntegrityError
                    ):
                        publication.status_plan(
                            state_root=self.root,
                            observer=observe,
                        )
                    with self.assertRaises(
                        publication.StableGitHubPublicationBoundaryIntegrityError
                    ):
                        publication.publish_plan(
                            execute_real_github_mutation=True,
                            expected_plan_sha256=self.plan.sha256(),
                            expected_results_sha256=self.plan.results_sha256,
                            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                            publication_order_ack=(
                                publication.ACK_PUBLICATION_ORDER
                            ),
                            state_root=self.root,
                            observer=observe,
                            mutator=remote.mutate,
                        )
        self.assertEqual(0, observations)
        self.assertEqual([], remote.mutations)
        build.assert_not_called()
        self.assertFalse((self.root / publication.LOCK_LEAF).exists())

    def test_delayed_exact_effect_resolves_trailing_intent_without_retry(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        remote.fail_before_effect = True
        with self.publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self.publish(remote)
            remote.index = 1
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, remote.index)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_effect_then_typed_cli_failure_is_reconciled_without_duplicate_call(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        remote.fail_after_effect = True
        with self.publisher_patches():
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_observation_failure_leaves_intent_for_later_exact_reconciliation(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )

        def mutate_then_hide(
            plan: publication.PublicationPlan,
            action: publication.MutationAction,
            before: publication.RemoteSnapshot,
        ) -> None:
            remote.mutate(plan, action, before)
            remote.fail_next_observation = True

        with self.publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=remote.observe,
                    mutator=mutate_then_hide,
                )
            self.assertEqual(1, len(remote.mutations))
            journal = self.root / publication.JOURNAL_DIRECTORY
            self.assertTrue((journal / "000000-reconciliation.json").exists())
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_policy_invalid_successor_observation_recovers_when_settled(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        policy_invalid = False

        def observe(
            plan: publication.PublicationPlan,
        ) -> publication.RemoteSnapshot:
            if policy_invalid:
                raise github_release.GitHubReleaseObservationError(
                    "synthetic starter asset policy violation"
                )
            return remote.observe(plan)

        def mutate_then_expose_starter(
            plan: publication.PublicationPlan,
            action: publication.MutationAction,
            before: publication.RemoteSnapshot,
        ) -> None:
            nonlocal policy_invalid
            remote.mutate(plan, action, before)
            policy_invalid = True

        journal = self.root / publication.JOURNAL_DIRECTORY
        with self.publisher_patches():
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationOutcomeUnknown,
                "policy-invalid",
            ):
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=observe,
                    mutator=mutate_then_expose_starter,
                )
            # A policy-invalid observation of a mutation that may have taken
            # effect records reconciliation authority (not a bare trailing
            # intent), so a later settled observation recovers it instead of
            # wedging the publication in permanent manual review.
            self.assertTrue((journal / "000000-intent.json").exists())
            self.assertTrue((journal / "000000-reconciliation.json").exists())
            self.assertFalse((journal / "000000-outcome.json").exists())
            policy_invalid = False
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, status.applied_actions)
        self.assertTrue((journal / "000000-outcome.json").exists())
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_invalid_successor_recovers_across_create_upload_and_publish(self) -> None:
        for target_index in (0, 2, 13):
            with self.subTest(target_index=target_index):
                for leaf in (self.root / publication.JOURNAL_DIRECTORY).iterdir():
                    leaf.unlink()
                remote = FakeRemote(
                    self.plan, self.root / publication.JOURNAL_DIRECTORY
                )
                invalid = False

                def observe(
                    plan: publication.PublicationPlan,
                ) -> publication.RemoteSnapshot:
                    snapshot = remote.observe(plan)
                    if not invalid:
                        return snapshot
                    return dataclasses.replace(
                        snapshot,
                        releases=dataclasses.replace(
                            snapshot.releases,
                            immutable_enabled=False,
                        ),
                    )

                def mutate_then_invalidate(
                    plan: publication.PublicationPlan,
                    action: publication.MutationAction,
                    before: publication.RemoteSnapshot,
                ) -> None:
                    nonlocal invalid
                    remote.mutate(plan, action, before)
                    if action.index == target_index:
                        invalid = True

                with self.publisher_patches():
                    with self.assertRaisesRegex(
                        publication.StableGitHubPublicationOutcomeUnknown,
                        "invalid or unclassifiable",
                    ):
                        publication.publish_plan(
                            execute_real_github_mutation=True,
                            expected_plan_sha256=self.plan.sha256(),
                            expected_results_sha256=self.plan.results_sha256,
                            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                            publication_order_ack=(
                                publication.ACK_PUBLICATION_ORDER
                            ),
                            state_root=self.root,
                            observer=observe,
                            mutator=mutate_then_invalidate,
                        )
                    journal = self.root / publication.JOURNAL_DIRECTORY
                    # The mutation may have taken effect while its immediate
                    # observation was invalid; reconciliation authority is
                    # recorded so a later settled observation recovers it.
                    self.assertTrue(
                        (journal / f"{target_index:06d}-intent.json").exists()
                    )
                    self.assertTrue(
                        (
                            journal
                            / f"{target_index:06d}-reconciliation.json"
                        ).exists()
                    )
                    self.assertFalse(
                        (journal / f"{target_index:06d}-outcome.json").exists()
                    )
                    # A subsequent settled observation reconciles the attempted
                    # mutation and drives the publication to completion.
                    status = self.publish(remote)
                self.assertTrue(status.complete)
                self.assertEqual(publication.MAX_ACTIONS, status.applied_actions)
                self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))
                self.assertTrue(
                    (journal / f"{target_index:06d}-outcome.json").exists()
                )

    def test_reconciliation_authority_keeps_invalid_remote_as_unknown(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        remote.fail_before_effect = True
        with self.publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self.publish(remote)
            invalid = fixture_snapshot(self.plan, 0)
            invalid = dataclasses.replace(
                invalid,
                releases=dataclasses.replace(
                    invalid.releases,
                    immutable_enabled=False,
                ),
            )
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationOutcomeUnknown,
                "cannot be classified",
            ):
                publication.publish_plan(
                    execute_real_github_mutation=True,
                    expected_plan_sha256=self.plan.sha256(),
                    expected_results_sha256=self.plan.results_sha256,
                    draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                    publication_order_ack=publication.ACK_PUBLICATION_ORDER,
                    state_root=self.root,
                    observer=lambda _plan: invalid,
                    mutator=remote.mutate,
                )
        self.assertEqual(1, len(remote.mutations))
        journal = self.root / publication.JOURNAL_DIRECTORY
        self.assertTrue((journal / "000000-reconciliation.json").exists())
        self.assertFalse((journal / "000000-outcome.json").exists())

    def test_selected_stop_indices_leave_one_exact_reconcilable_prefix(self) -> None:
        for stop_index in (0, 1, 2, 5, 6, 12, 13, 14):
            with self.subTest(stop_index=stop_index):
                for leaf in (self.root / publication.JOURNAL_DIRECTORY).iterdir():
                    leaf.unlink()
                remote = FakeRemote(
                    self.plan, self.root / publication.JOURNAL_DIRECTORY
                )

                def stop_at_selected_action(
                    plan: publication.PublicationPlan,
                    action: publication.MutationAction,
                    before: publication.RemoteSnapshot,
                ) -> None:
                    if action.index == stop_index:
                        remote.fail_before_effect = True
                    remote.mutate(plan, action, before)

                with self.publisher_patches():
                    with self.assertRaises(
                        publication.StableGitHubPublicationOutcomeUnknown
                    ):
                        publication.publish_plan(
                            execute_real_github_mutation=True,
                            expected_plan_sha256=self.plan.sha256(),
                            expected_results_sha256=self.plan.results_sha256,
                            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
                            publication_order_ack=(
                                publication.ACK_PUBLICATION_ORDER
                            ),
                            state_root=self.root,
                            observer=remote.observe,
                            mutator=stop_at_selected_action,
                        )
                self.assertEqual(stop_index, remote.index)
                self.assertEqual(stop_index + 1, len(remote.mutations))
                journal = self.root / publication.JOURNAL_DIRECTORY
                for completed in range(stop_index):
                    self.assertTrue(
                        (journal / f"{completed:06d}-intent.json").exists()
                    )
                    self.assertTrue(
                        (journal / f"{completed:06d}-outcome.json").exists()
                    )
                self.assertTrue(
                    (journal / f"{stop_index:06d}-intent.json").exists()
                )
                self.assertTrue(
                    (
                        journal
                        / f"{stop_index:06d}-reconciliation.json"
                    ).exists()
                )
                self.assertFalse(
                    (journal / f"{stop_index:06d}-outcome.json").exists()
                )

    def test_crash_after_durable_intent_is_manual_only_at_five_boundaries(self) -> None:
        original_write_intent = publication._write_intent
        for crash_index in (0, 1, 5, 13, 14):
            with self.subTest(crash_index=crash_index):
                for leaf in (self.root / publication.JOURNAL_DIRECTORY).iterdir():
                    leaf.unlink()
                remote = FakeRemote(
                    self.plan, self.root / publication.JOURNAL_DIRECTORY
                )

                def write_then_crash(
                    directory: PrivateDirectoryHandle,
                    plan: publication.PublicationPlan,
                    action: publication.MutationAction,
                    before: publication.RemoteSnapshot,
                ) -> dict[str, object]:
                    record = original_write_intent(
                        directory,
                        plan,
                        action,
                        before,
                    )
                    if action.index == crash_index:
                        raise RuntimeError("synthetic crash after durable intent")
                    return record

                with self.publisher_patches():
                    with (
                        mock.patch.object(
                            publication,
                            "_write_intent",
                            side_effect=write_then_crash,
                        ),
                        self.assertRaisesRegex(
                            RuntimeError,
                            "crash after durable intent",
                        ),
                    ):
                        self.publish(remote)
                    self.assertEqual(crash_index, remote.index)
                    self.assertEqual(crash_index, len(remote.mutations))
                    with self.assertRaisesRegex(
                        publication.StableGitHubPublicationOutcomeUnknown,
                        "manual review",
                    ):
                        self.publish(remote)
                journal = self.root / publication.JOURNAL_DIRECTORY
                self.assertTrue(
                    (journal / f"{crash_index:06d}-intent.json").exists()
                )
                self.assertFalse(
                    (
                        journal
                        / f"{crash_index:06d}-reconciliation.json"
                    ).exists()
                )
                self.assertFalse(
                    (journal / f"{crash_index:06d}-outcome.json").exists()
                )

    def test_crash_after_reconciliation_authority_recovers_without_retry(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        with self.publisher_patches():
            with (
                mock.patch.object(
                    publication,
                    "_write_outcome",
                    side_effect=RuntimeError(
                        "synthetic crash before durable outcome"
                    ),
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "crash before durable outcome",
                ),
            ):
                self.publish(remote)
            journal = self.root / publication.JOURNAL_DIRECTORY
            self.assertTrue((journal / "000000-intent.json").exists())
            self.assertTrue(
                (journal / "000000-reconciliation.json").exists()
            )
            self.assertFalse((journal / "000000-outcome.json").exists())
            self.assertEqual(1, remote.index)
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_committed_reconciliation_then_error_recovers_without_retry(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        original = publication._write_reconciliation_authority

        def commit_then_error(
            directory: PrivateDirectoryHandle,
            plan: publication.PublicationPlan,
            action: publication.MutationAction,
            intent: Mapping[str, object],
            *,
            cli_failure: github_release.GitHubCliExecutionError | None,
        ) -> dict[str, object]:
            record = original(
                directory,
                plan,
                action,
                intent,
                cli_failure=cli_failure,
            )
            if action.index == 0:
                raise RuntimeError("synthetic error after reconciliation commit")
            return record

        with self.publisher_patches():
            with (
                mock.patch.object(
                    publication,
                    "_write_reconciliation_authority",
                    side_effect=commit_then_error,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "error after reconciliation commit",
                ),
            ):
                self.publish(remote)
            self.assertEqual(1, remote.index)
            self.assertEqual(1, len(remote.mutations))
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_committed_outcome_then_error_recovers_without_retry(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        original = publication._write_outcome

        def commit_then_error(
            directory: PrivateDirectoryHandle,
            plan: publication.PublicationPlan,
            action: publication.MutationAction,
            intent: Mapping[str, object],
            observed: publication.RemoteSnapshot,
            *,
            cli_failure: github_release.GitHubCliExecutionError | None = None,
            execution: Mapping[str, object] | None = None,
        ) -> dict[str, object]:
            record = original(
                directory,
                plan,
                action,
                intent,
                observed,
                cli_failure=cli_failure,
                execution=execution,
            )
            if action.index == 13:
                raise RuntimeError("synthetic error after outcome commit")
            return record

        with self.publisher_patches():
            with (
                mock.patch.object(
                    publication,
                    "_write_outcome",
                    side_effect=commit_then_error,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "error after outcome commit",
                ),
            ):
                self.publish(remote)
            self.assertEqual(14, remote.index)
            self.assertEqual(14, len(remote.mutations))
            status = self.publish(remote)
        self.assertTrue(status.complete)
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_explicit_execution_plan_results_and_both_acknowledgements_are_required(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        base = dict(
            execute_real_github_mutation=True,
            expected_plan_sha256=self.plan.sha256(),
            expected_results_sha256=self.plan.results_sha256,
            draft_barrier_ack=publication.ACK_DRAFT_BARRIER,
            publication_order_ack=publication.ACK_PUBLICATION_ORDER,
            state_root=self.root,
            observer=remote.observe,
            mutator=remote.mutate,
        )
        mutations = (
            {"execute_real_github_mutation": False},
            {"expected_plan_sha256": _digest(b"wrong plan")},
            {"expected_results_sha256": _digest(b"wrong results")},
            {"draft_barrier_ack": "wrong"},
            {"publication_order_ack": "wrong"},
        )
        with self.publisher_patches():
            for changed in mutations:
                arguments = {**base, **changed}
                with self.assertRaises(publication.StableGitHubPublicationError):
                    publication.publish_plan(**arguments)
        self.assertEqual([], remote.mutations)

    def test_status_and_verify_are_strictly_read_only(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        with (
            self.publisher_patches(),
            mock.patch.object(
                publication.os,
                "fsync",
                side_effect=AssertionError("read-only command called fsync"),
            ) as fsync,
            mock.patch.object(
                publication.os,
                "unlink",
                side_effect=AssertionError("read-only command unlinked state"),
            ) as unlink,
            mock.patch.object(
                publication,
                "write_private_json_noreplace_at",
                side_effect=AssertionError("read-only command wrote state"),
            ) as writer,
        ):
            status = publication.status_plan(
                state_root=self.root,
                observer=remote.observe,
            )
            self.assertFalse(status.complete)
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError,
                "not complete",
            ):
                publication.verify_publication(
                    state_root=self.root,
                    observer=remote.observe,
                )
        fsync.assert_not_called()
        unlink.assert_not_called()
        writer.assert_not_called()
        self.assertEqual([], remote.mutations)

    def test_transition_rejects_same_successor_index_with_recreated_release(self) -> None:
        before = fixture_snapshot(self.plan, 2)
        recreated = fixture_snapshot(self.plan, 3, apple_release_id=999)
        action = publication.MutationAction(
            index=2,
            action_id="upload-apple-00-APPLE_DISTRIBUTION.json",
            kind="upload",
            domain="apple",
            asset_index=0,
        )
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "outside the admitted mutation",
        ):
            publication.validate_exact_remote_transition(
                self.plan,
                action,
                publication._remote_projection(before),
                recreated,
            )

    def test_plan_parser_recomputes_request_authority(self) -> None:
        document = self.plan.document()
        document["releases"][0]["create_request"]["sha256"] = _digest(
            b"forged request"
        )
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError,
            "fixed canonical bytes",
        ):
            publication.parse_plan(document)

        for mutation in (
            "tag",
            "body",
            "make_latest",
            "extra_request_field",
            "forged_draft_request",
        ):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(self.plan.document()))
                apple = changed["releases"][0]
                if mutation == "tag":
                    apple["tag"] = "wrong-tag"
                elif mutation == "body":
                    apple["body"] = "wrong body"
                elif mutation == "make_latest":
                    apple["make_latest"] = False
                elif mutation == "extra_request_field":
                    apple["create_request"]["extra"] = True
                else:
                    forged = canonical_json_bytes(
                        {
                            "body": publication.APPLE_BODY,
                            "draft": False,
                            "make_latest": "true",
                            "name": publication.APPLE_TITLE,
                            "tag_name": self.plan.apple.tag,
                        }
                    )
                    apple["create_request"]["bytes"] = len(forged)
                    apple["create_request"]["sha256"] = _digest(forged)
                with self.assertRaises(
                    publication.StableGitHubPublicationError
                ):
                    publication.parse_plan(changed)

    def test_journal_rejects_boolean_sequence_fields_without_retry(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        remote.fail_before_effect = True
        with self.publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self.publish(remote)
            intent_path = (
                self.root / publication.JOURNAL_DIRECTORY / "000000-intent.json"
            )
            intent = json.loads(intent_path.read_bytes())
            intent["pre_index"] = True
            intent_path.write_bytes(canonical_json_bytes(intent))
            os.chmod(intent_path, 0o600)
            with self.assertRaises(publication.StableGitHubPublicationError):
                self.publish(remote)
        self.assertEqual(1, len(remote.mutations))

    def test_journal_rejects_unknown_reconciliation_error_kind(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        remote.fail_before_effect = True
        with self.publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self.publish(remote)
            reconciliation_path = (
                self.root
                / publication.JOURNAL_DIRECTORY
                / "000000-reconciliation.json"
            )
            reconciliation = json.loads(reconciliation_path.read_bytes())
            reconciliation["execution"]["error_kind"] = "unknown"
            reconciliation_path.write_bytes(canonical_json_bytes(reconciliation))
            os.chmod(reconciliation_path, 0o600)
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError,
                "failure classification",
            ):
                self.publish(remote)
        self.assertEqual(1, len(remote.mutations))

    def test_applied_outcome_requires_matching_reconciliation_authority(self) -> None:
        remote = FakeRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        with self.publisher_patches():
            self.assertTrue(self.publish(remote).complete)
            journal = self.root / publication.JOURNAL_DIRECTORY
            reconciliation_path = journal / "000004-reconciliation.json"
            reconciliation_bytes = reconciliation_path.read_bytes()
            reconciliation_path.unlink()
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError,
                "lacks reconciliation authority",
            ):
                publication.status_plan(
                    state_root=self.root,
                    observer=remote.observe,
                )
            reconciliation_path.write_bytes(reconciliation_bytes)
            os.chmod(reconciliation_path, 0o600)
            outcome_path = journal / "000004-outcome.json"
            outcome = json.loads(outcome_path.read_bytes())
            outcome["execution"] = {
                "error_kind": "timeout",
                "returncode": None,
                "status": "cli_failure_reconciled",
            }
            outcome_path.write_bytes(canonical_json_bytes(outcome))
            os.chmod(outcome_path, 0o600)
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError,
                "differs from its reconciliation authority",
            ):
                publication.status_plan(
                    state_root=self.root,
                    observer=remote.observe,
                )
        self.assertEqual(publication.MAX_ACTIONS, len(remote.mutations))

    def test_cli_usage_errors_are_fixed_and_never_echo_argv(self) -> None:
        sentinel = f"GH_TOKEN=fixture_secret:{self.root}"
        cases = (
            [
                "publish",
                "--execute-real",
                f"--unknown={sentinel}",
            ],
            [sentinel],
            [
                "publish",
                "--expected-plan-sha256",
                f"--unknown={sentinel}",
            ],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                output = io.StringIO()
                error_output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(error_output),
                    self.assertRaises(SystemExit) as caught,
                ):
                    publication.main(arguments)
                self.assertEqual(2, caught.exception.code)
                self.assertEqual("", output.getvalue())
                self.assertEqual(
                    "STABLE_GITHUB_USAGE_ERROR error_type=ArgumentError\n",
                    error_output.getvalue(),
                )
                self.assertNotIn(sentinel, error_output.getvalue())
                self.assertNotIn("fixture_secret", error_output.getvalue())
                self.assertNotIn(str(self.root), error_output.getvalue())

        error_output = io.StringIO()
        with (
            contextlib.redirect_stderr(error_output),
            self.assertRaises(SystemExit) as abbreviated,
        ):
            publication.main(["publish", "--execute-real"])
        self.assertEqual(2, abbreviated.exception.code)
        self.assertEqual(
            "STABLE_GITHUB_USAGE_ERROR error_type=ArgumentError\n",
            error_output.getvalue(),
        )

    def test_prepare_state_bootstrap_creates_only_fixed_private_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            expected = base / ".q-periapt" / "publication-state" / "github-stable-v0.1.4"
            with (
                mock.patch.object(
                    publication, "expected_state_root", return_value=expected
                ),
                mock.patch.object(
                    publication, "_registered_worktrees", return_value=()
                ),
            ):
                observed, created = publication.ensure_state_root_for_prepare(
                    expected
                )
            self.assertEqual(expected, observed)
            self.assertIsInstance(
                created,
                publication.PrivateSafeRootCreatedIdentity,
            )
            for directory in (expected.parent.parent, expected.parent, expected):
                self.assertTrue(directory.is_dir())
                self.assertEqual(0o700, directory.stat().st_mode & 0o777)

    def test_created_state_identity_rejects_root_replacement_before_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            expected = (
                base
                / ".q-periapt"
                / "publication-state"
                / "github-stable-v0.1.4"
            )
            with (
                mock.patch.object(
                    publication,
                    "expected_state_root",
                    return_value=expected,
                ),
                mock.patch.object(
                    publication,
                    "_registered_worktrees",
                    return_value=(),
                ),
            ):
                root, identity = publication.ensure_state_root_for_prepare(
                    expected
                )
                if identity is None:
                    self.fail("fresh state root lacked its created identity")
                moved = expected.parent / "github-stable-v0.1.4.moved"
                expected.rename(moved)
                expected.mkdir(mode=0o700)
                os.chmod(expected, 0o700)
                with (
                    mock.patch.object(
                        publication,
                        "ensure_state_root_for_prepare",
                        return_value=(root, identity),
                    ),
                    mock.patch.object(
                        publication,
                        "build_plan_from_pending_results",
                        side_effect=AssertionError(
                            "replacement root reached source loading"
                        ),
                    ) as build,
                    self.assertRaises(
                        publication.StableGitHubPublicationBoundaryIntegrityError
                    ),
                ):
                    publication.prepare_plan(
                        self.plan.results_sha256,
                        state_root=expected,
                    )
                build.assert_not_called()
                self.assertFalse((expected / publication.LOCK_LEAF).exists())
                self.assertFalse((moved / publication.LOCK_LEAF).exists())

    def test_two_bootstrap_callers_share_one_persistent_lock_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            expected = (
                base
                / ".q-periapt"
                / "publication-state"
                / "github-stable-v0.1.4"
            )
            with (
                mock.patch.object(
                    publication,
                    "expected_state_root",
                    return_value=expected,
                ),
                mock.patch.object(
                    publication,
                    "_registered_worktrees",
                    return_value=(),
                ),
            ):
                first_root, first_identity = (
                    publication.ensure_state_root_for_prepare(expected)
                )
                second_root, second_identity = (
                    publication.ensure_state_root_for_prepare(expected)
                )
                if first_identity is None:
                    self.fail("first bootstrap lacked its created identity")
                self.assertIsNone(second_identity)
                with publication.publication_lock(
                    first_root,
                    allow_create=True,
                    created_root_identity=first_identity,
                ) as first_lock:
                    with self.assertRaises(
                        publication.StableGitHubPublicationLockHeld
                    ):
                        with publication.publication_lock(
                            second_root,
                            allow_create=False,
                        ):
                            self.fail("second bootstrap acquired a split lock")
                    named = (expected / publication.LOCK_LEAF).stat()
                    self.assertEqual(first_lock.lock_inode, named.st_ino)
                    self.assertEqual(first_lock.lock_device, named.st_dev)

    def test_crash_after_root_mkdir_before_lock_requires_manual_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            expected = (
                base
                / ".q-periapt"
                / "publication-state"
                / "github-stable-v0.1.4"
            )
            with (
                mock.patch.object(
                    publication,
                    "expected_state_root",
                    return_value=expected,
                ),
                mock.patch.object(
                    publication,
                    "_registered_worktrees",
                    return_value=(),
                ),
            ):
                _root, identity = publication.ensure_state_root_for_prepare(
                    expected
                )
                self.assertIsNotNone(identity)
                self.assertEqual([], list(expected.iterdir()))
                with (
                    mock.patch.object(
                        publication,
                        "build_plan_from_pending_results",
                        side_effect=AssertionError(
                            "empty-root residue reached source loading"
                        ),
                    ) as build,
                    mock.patch.object(
                        github_release,
                        "github_cli_environment",
                        side_effect=AssertionError(
                            "empty-root residue reached credentials"
                        ),
                    ) as credential_boundary,
                    mock.patch.object(
                        publication,
                        "observe_remote_transaction",
                        side_effect=AssertionError(
                            "empty-root residue reached remote observation"
                        ),
                    ) as observer,
                    self.assertRaises(
                        publication.StableGitHubPublicationBoundaryIntegrityError
                    ),
                ):
                    publication.prepare_plan(
                        self.plan.results_sha256,
                        state_root=expected,
                    )
                build.assert_not_called()
                credential_boundary.assert_not_called()
                observer.assert_not_called()
                self.assertEqual([], list(expected.iterdir()))

    def _install_complete_preparation_prefix(self) -> None:
        (self.root / publication.PLAN_LEAF).unlink()
        intent = {
            "kind": "qperiapt.stable_github_preparation_intent",
            "plan": self.plan.document(),
            "plan_sha256": self.plan.sha256(),
            "schema_version": 1,
        }
        intent_path = self.root / publication.PREPARATION_INTENT_LEAF
        intent_path.write_bytes(canonical_json_bytes(intent))
        os.chmod(intent_path, 0o600)
        for release_index, release in enumerate(self.plan.releases):
            seed = 11 if release_index == 0 else 31
            for asset_index, asset in enumerate(release.assets):
                payload = bytes([seed + asset_index]) * asset.size
                self.assertEqual(asset.sha256, _digest(payload))
                path = (
                    self.root
                    / publication.STAGING_DIRECTORY
                    / asset.staging_leaf
                )
                path.write_bytes(payload)
                os.chmod(path, 0o600)
        for leaf, payload in publication._request_payloads(self.plan).items():
            path = self.root / publication.REQUEST_DIRECTORY / leaf
            path.write_bytes(payload)
            os.chmod(path, 0o600)

    def test_first_prepare_stages_exact_eleven_assets_and_four_requests_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary).resolve()
            expected = (
                base
                / ".q-periapt"
                / "publication-state"
                / "github-stable-v0.1.4"
            )
            apple_snapshots = tuple(
                publication.FileSnapshot(
                    path=pathlib.Path(asset.name),
                    data=bytes([11 + index]) * asset.size,
                    size=asset.size,
                    sha256=asset.sha256,
                )
                for index, asset in enumerate(self.plan.apple.assets)
            )

            def stage_platform(
                _candidate: object,
                _source: object,
                **kwargs: object,
            ) -> object:
                directory_fd = kwargs["staging_directory_fd"]
                leaves = kwargs["staging_leaves"]
                self.assertIsInstance(directory_fd, int)
                self.assertIsInstance(leaves, dict)
                for index, asset in enumerate(self.plan.platform.assets):
                    payload = bytes([31 + index]) * asset.size
                    publication.write_private_bytes_noreplace_at(
                        directory_fd,
                        leaves[asset.name],
                        payload,
                        label=f"fixture platform asset {asset.name}",
                        maximum=asset.size,
                    )
                return object()

            with (
                mock.patch.object(
                    publication,
                    "expected_state_root",
                    return_value=expected,
                ),
                mock.patch.object(
                    publication,
                    "_registered_worktrees",
                    return_value=(),
                ),
                mock.patch.object(
                    publication,
                    "build_plan_from_pending_results",
                    return_value=(
                        self.plan,
                        apple_snapshots,
                        {"candidate": "P-selected"},
                        {"source": "P-selected"},
                    ),
                ) as build,
                mock.patch.object(
                    publication.platform_distribution,
                    "find_selected_release_candidate_bundle",
                    side_effect=stage_platform,
                ) as platform_stager,
                mock.patch.object(
                    publication,
                    "verify_local_plan",
                    return_value=None,
                ),
                mock.patch.object(
                    github_release,
                    "github_cli_environment",
                    side_effect=AssertionError(
                        "prepare entered the credential boundary"
                    ),
                ) as credential_boundary,
                mock.patch.object(
                    publication,
                    "observe_remote_transaction",
                    side_effect=AssertionError("prepare observed the network"),
                ) as remote_observer,
            ):
                prepared = publication.prepare_plan(
                    self.plan.results_sha256,
                    state_root=expected,
                )
            self.assertEqual(self.plan, prepared)
            build.assert_called_once_with(self.plan.results_sha256)
            platform_stager.assert_called_once()
            credential_boundary.assert_not_called()
            remote_observer.assert_not_called()
            staged = expected / publication.STAGING_DIRECTORY
            expected_assets = {
                asset.staging_leaf: asset.sha256
                for release in self.plan.releases
                for asset in release.assets
            }
            self.assertEqual(set(expected_assets), {path.name for path in staged.iterdir()})
            for leaf, digest in expected_assets.items():
                self.assertEqual(digest, _digest((staged / leaf).read_bytes()))
            requests = expected / publication.REQUEST_DIRECTORY
            self.assertEqual(
                set(publication._request_payloads(self.plan)),
                {path.name for path in requests.iterdir()},
            )

    def test_prepare_recovers_complete_durable_prefix_without_source_caches(self) -> None:
        self._install_complete_preparation_prefix()
        with (
            mock.patch.object(
                publication, "expected_state_root", return_value=self.root
            ),
            mock.patch.object(publication, "_registered_worktrees", return_value=()),
            mock.patch.object(
                publication,
                "_validate_plan_against_current_pending",
                return_value=None,
            ),
            mock.patch.object(
                publication,
                "build_plan_from_pending_results",
                side_effect=AssertionError("source cache must not be reopened"),
            ) as build,
            mock.patch.object(publication, "verify_local_plan", return_value=None),
            mock.patch.object(
                github_release,
                "github_cli_environment",
                side_effect=AssertionError("credential boundary must stay closed"),
            ) as credential_boundary,
            mock.patch.object(
                publication,
                "observe_remote_transaction",
                side_effect=AssertionError("prepare must not observe the network"),
            ) as remote_observer,
        ):
            recovered = publication.prepare_plan(
                self.plan.results_sha256,
                state_root=self.root,
            )
        self.assertEqual(self.plan, recovered)
        build.assert_not_called()
        credential_boundary.assert_not_called()
        remote_observer.assert_not_called()
        self.assertEqual(
            canonical_json_bytes(self.plan.document()),
            (self.root / publication.PLAN_LEAF).read_bytes(),
        )

    def test_prepare_partial_prefix_requires_original_source_authority(self) -> None:
        self._install_complete_preparation_prefix()
        missing = self.plan.platform.assets[-1].staging_leaf
        (self.root / publication.STAGING_DIRECTORY / missing).unlink()
        with (
            mock.patch.object(
                publication, "expected_state_root", return_value=self.root
            ),
            mock.patch.object(publication, "_registered_worktrees", return_value=()),
            mock.patch.object(
                publication,
                "_validate_plan_against_current_pending",
                return_value=None,
            ),
            mock.patch.object(
                publication,
                "build_plan_from_pending_results",
                side_effect=publication.StableGitHubPublicationError(
                    "selected source cache is unavailable"
                ),
            ) as build,
        ):
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError,
                "source cache is unavailable",
            ):
                publication.prepare_plan(
                    self.plan.results_sha256,
                    state_root=self.root,
                )
        build.assert_called_once_with(self.plan.results_sha256)
        self.assertFalse((self.root / publication.PLAN_LEAF).exists())

    def test_production_mutator_uses_pinned_root_for_all_three_action_kinds(self) -> None:
        apple_payload = bytes([11]) * 11
        apple_asset = self.plan.apple.assets[0]
        self.assertEqual(apple_asset.sha256, _digest(apple_payload))
        (self.root / publication.STAGING_DIRECTORY / apple_asset.staging_leaf).write_bytes(
            apple_payload
        )
        os.chmod(
            self.root / publication.STAGING_DIRECTORY / apple_asset.staging_leaf,
            0o600,
        )
        for release in self.plan.releases:
            for request in (release.create_request, release.publish_request):
                payload = publication._request_payloads(self.plan)[request.leaf]
                path = self.root / publication.REQUEST_DIRECTORY / request.leaf
                path.write_bytes(payload)
                os.chmod(path, 0o600)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        metadata = os.fstat(root_fd)
        root_handle = PrivateDirectoryHandle(
            path=self.root,
            descriptor=root_fd,
            parent_descriptor=-1,
            name=self.root.name,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=0o700,
        )
        json_calls: list[dict[str, object]] = []
        upload_calls: list[dict[str, object]] = []

        def consume_json(_tool: object, **kwargs: object) -> bytes:
            json_calls.append(kwargs)
            os.lseek(kwargs["input_fd"], kwargs["input_size"], os.SEEK_SET)
            return b""

        def consume_upload(_tool: object, **kwargs: object) -> bytes:
            upload_calls.append(kwargs)
            os.lseek(kwargs["input_fd"], kwargs["input_size"], os.SEEK_SET)
            return b""

        tool = github_release.GitHubCliIdentity(
            path="/fixed/gh",
            device=1,
            inode=2,
            mode=0o100500,
            uid=os.geteuid(),
            link_count=1,
            size=1,
            sha256=self.plan.github_cli_sha256,
        )
        try:
            with (
                mock.patch.object(
                    github_release, "select_github_cli", return_value=tool
                ),
                mock.patch.object(
                    github_release,
                    "github_cli_environment",
                    return_value={"GH_TOKEN": "not-recorded"},
                ),
                mock.patch.object(
                    github_release,
                    "execute_github_api_json_mutation",
                    side_effect=consume_json,
                ),
                mock.patch.object(
                    github_release,
                    "execute_github_api_asset_upload",
                    side_effect=consume_upload,
                ),
            ):
                publication.execute_production_mutation(
                    root_handle,
                    self.plan,
                    publication.MutationAction(
                        0,
                        "create-apple-draft",
                        "create",
                        "apple",
                    ),
                    fixture_snapshot(self.plan, 0),
                    source_environment={"GH_TOKEN": "fixture"},
                )
                publication.execute_production_mutation(
                    root_handle,
                    self.plan,
                    publication.MutationAction(
                        2,
                        "upload-apple-00-APPLE_DISTRIBUTION.json",
                        "upload",
                        "apple",
                        0,
                    ),
                    fixture_snapshot(self.plan, 2),
                    source_environment={"GH_TOKEN": "fixture"},
                )
                publication.execute_production_mutation(
                    root_handle,
                    self.plan,
                    publication.MutationAction(
                        13,
                        "publish-apple",
                        "publish",
                        "apple",
                    ),
                    fixture_snapshot(self.plan, 13),
                    source_environment={"GH_TOKEN": "fixture"},
                )
                create_path = (
                    self.root
                    / publication.REQUEST_DIRECTORY
                    / self.plan.apple.create_request.leaf
                )
                create_path.write_bytes(
                    publication._request_payloads(self.plan)[
                        self.plan.apple.create_request.leaf
                    ]
                    + b" "
                )
                os.chmod(create_path, 0o600)
                with self.assertRaises(PublicationReceiptIOError):
                    publication.execute_production_mutation(
                        root_handle,
                        self.plan,
                        publication.MutationAction(
                            0,
                            "create-apple-draft",
                            "create",
                            "apple",
                        ),
                        fixture_snapshot(self.plan, 0),
                        source_environment={"GH_TOKEN": "fixture"},
                    )
        finally:
            os.close(root_fd)
        self.assertEqual(["POST", "PATCH"], [call["method"] for call in json_calls])
        self.assertEqual(
            publication.JSON_MUTATION_TIMEOUT_SECONDS,
            json_calls[0]["timeout_seconds"],
        )
        self.assertEqual(
            publication.ASSET_UPLOAD_TIMEOUT_SECONDS,
            upload_calls[0]["timeout_seconds"],
        )
        self.assertEqual(101, upload_calls[0]["release_id"])
        self.assertEqual(apple_asset.sha256, upload_calls[0]["input_sha256"])


if __name__ == "__main__":
    unittest.main()
