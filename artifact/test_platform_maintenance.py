"""Compatibility, revision authority and ambiguous-outcome regression tests."""

from __future__ import annotations

import copy
import argparse
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import tempfile
import pathlib
import subprocess
import unittest
from unittest import mock

import apple_distribution
import apple_stable_publication
import git_provenance
import github_release_observation as github
import platform_distribution_contract as distribution_contract
import test_apple_stable_publication as apple_fixtures
import platform_maintenance_contract as maintenance
import platform_maintenance as maintenance_source
import platform_distribution as distribution
import platform_stable_publication as collector
import platform_stable_publication_contract as platform
import proof_manifest
import release_publication_contract as release
import release_receipt_finalizer as finalizer
import stable_github_publication as publication
import test_github_release_observation as github_fixtures
import test_platform_distribution as distribution_fixtures
import test_release_receipt_finalizer as finalizer_fixtures
import test_release_publication_contract as release_fixtures
from publication_receipt_io import canonical_json_bytes
from test_platform_stable_publication_contract import pending_receipt, verified_receipt
import test_stable_github_publication as stable_fixtures
from test_stable_github_publication import fixture_plan, fixture_snapshot


PROFILE = publication.PlatformReleaseProfile.MAINTENANCE_R2
EXPECTED_ACTIONS = (
    "create-platform-draft",
    "upload-platform-00-PLATFORM_DISTRIBUTION.json",
    "upload-platform-01-SHA256SUMS",
    "upload-platform-02-q-periapt-android-0.1.5-16k-runtime-evidence.zip",
    "upload-platform-03-q-periapt-android-0.1.5-MANIFEST.json",
    "upload-platform-04-q-periapt-android-0.1.5.aar",
    "upload-platform-05-q-periapt-c-abi2-0.1.5-aarch64-unknown-linux-gnu.tar.gz",
    "upload-platform-06-q-periapt-c-abi2-0.1.5-x86_64-unknown-linux-gnu.tar.gz",
    "publish-platform",
)


def revision_receipt(
    *,
    verified: bool = False,
    release_profile: publication.PlatformReleaseProfile = PROFILE,
) -> dict[str, object]:
    value = verified_receipt() if verified else pending_receipt()
    value["identity"] = release_profile.identity()
    value["boundary"] = platform.publication_boundary(release_profile)
    candidate = value["observation"]["candidate_attestation"]
    candidate["certificate_san"] = release_profile.workflow_uri
    candidate["signer_workflow"] = release_profile.workflow_uri
    candidate["source_ref"] = release_profile.release_ref
    source = value["observation"]["source"]
    runtime = value["observation"]["release_candidate"]["android_runtime_evidence"]
    consumers = {}
    for profile, run, tests in (
        (
            "agp_full_release",
            "a",
            [
                "runtimeMetadataMatches",
                "signedPolicyDecisionIsExactAndFailClosed",
                "osRandomPolicyRoundtripAndWipes",
            ],
        ),
        ("agp_minimal_release", "b", ["runtimeVersionOnly"]),
    ):
        consumers[profile] = {
            "proof_path": f"consumers/{profile}/proof.json",
            "projection": {
                "profile": profile,
                "proof_sha256": run * 64,
                "run_id": run * 32,
                "source_commit": source["tag_commit"],
                "source_tree_sha256": source["canonical_source_tree_sha256"],
                "aar_sha256": runtime["tested_aar_sha256"],
                "aar_manifest_sha256": runtime["tested_aar_manifest_sha256"],
                "apk_sha256": run * 64,
                "build_receipt_sha256": run * 64,
                "result_json_sha256": run * 64,
                "passed_tests": tests,
                "agp_version": "9.4.0",
                "gradle_version": "9.7.1",
            },
        }
    runtime["bundle_schema"] = 3
    runtime["agp_consumers"] = consumers
    if verified:
        value["observation"]["android_runtime_evidence"] = copy.deepcopy(runtime)
        value["observation"]["release_attestation"]["subjects"][0][
            "uri"
        ] = release_profile.tag_subject_uri
    return maintenance.wrap_publication(value, profile=release_profile)


def maintenance_plan(
    *,
    release_profile: publication.PlatformReleaseProfile = PROFILE,
) -> publication.PublicationPlan:
    original = fixture_plan()
    mutable = original.platform
    title, body = publication._platform_release_text(release_profile)
    common = {
        "tag": release_profile.release_tag,
        "title": title,
        "body": body,
        "make_latest": False,
        "tag_commit": original.tag_commit,
    }
    revised = dataclasses.replace(
        mutable,
        tag=common["tag"],
        title=common["title"],
        body=common["body"],
        create_request=publication._request_plan(
            "create-platform.json", publication._create_request_bytes(**common)
        ),
        publish_request=publication._request_plan(
            "publish-platform.json", publication._publish_request_bytes(**common)
        ),
    )
    return dataclasses.replace(
        original,
        profile=release_profile,
        releases=(publication._maintenance_apple_reference(), revised),
    )


def maintenance_snapshot(
    plan: publication.PublicationPlan, index: int
) -> publication.RemoteSnapshot:
    final = fixture_snapshot(
        plan, 15, apple_release_id=383170350, platform_release_id=400000001
    )
    apple, platform_view = final.releases.releases
    apple_raw = json.loads(apple.canonical)
    apple_raw["target_commitish"] = maintenance.BASE_TAG_COMMIT
    apple = dataclasses.replace(apple, canonical=canonical_json_bytes(apple_raw))
    if index == 0:
        platform_view = None
    elif index < 9:
        raw = json.loads(platform_view.canonical)
        raw.update(
            draft=True,
            immutable=False,
            is_latest=False,
            published_at=None,
            assets=raw["assets"][: index - 1],
        )
        platform_view = dataclasses.replace(
            platform_view,
            draft=True,
            immutable=False,
            is_latest=False,
            published_at=None,
            assets=platform_view.assets[: index - 1],
            canonical=canonical_json_bytes(raw),
        )
    canonical = json.loads(final.releases.canonical)
    canonical["releases"] = [
        json.loads(apple.canonical),
        None if platform_view is None else json.loads(platform_view.canonical),
    ]
    observation = dataclasses.replace(
        final.releases,
        releases=(apple, platform_view),
        canonical=canonical_json_bytes(canonical),
    )
    return dataclasses.replace(final, releases=observation)


class MaintenanceRemote:
    def __init__(
        self, plan: publication.PublicationPlan, journal: pathlib.Path
    ) -> None:
        self.plan, self.journal = plan, journal
        self.index = 0
        self.mutations: list[str] = []
        self.fail_after_effect = False
        self.fail_next_observation = False

    def observe(self, plan: publication.PublicationPlan) -> publication.RemoteSnapshot:
        if self.fail_next_observation:
            self.fail_next_observation = False
            raise github.GitHubCliExecutionError(
                "maintenance observation unavailable",
                error_kind="timeout",
                returncode=None,
            )
        if plan != self.plan:
            raise AssertionError("observer received a different plan")
        return maintenance_snapshot(plan, self.index)

    def mutate(
        self,
        plan: publication.PublicationPlan,
        action: publication.MutationAction,
        before: publication.RemoteSnapshot,
    ) -> None:
        if (
            action.action_id != EXPECTED_ACTIONS[self.index]
            or action.domain != "platform"
        ):
            raise AssertionError(
                "maintenance action differs from the independent oracle"
            )
        if before != maintenance_snapshot(plan, self.index):
            raise AssertionError("maintenance mutation predecessor differs")
        intent = self.journal / f"{self.index:06d}-intent.json"
        if (
            not intent.is_file()
            or (self.journal / f"{self.index:06d}-outcome.json").exists()
        ):
            raise AssertionError(
                "maintenance mutation lacks its durable intent boundary"
            )
        self.mutations.append(action.action_id)
        self.index += 1
        if self.fail_after_effect:
            self.fail_after_effect = False
            self.fail_next_observation = True
            raise github.GitHubCliExecutionError(
                "uncertain maintenance response", error_kind="timeout", returncode=None
            )


class PlatformMaintenanceContractTests(unittest.TestCase):
    def test_exact_frozen_q_bytes_and_all_three_domains_remain_valid(self) -> None:
        raw = (
            pathlib.Path(__file__).parent / "fixtures/published-v0.1.5-results.json"
        ).read_bytes()
        before = hashlib.sha256(raw).hexdigest()
        self.assertEqual(
            "90f5faed852311a59f388eaf79072c4887aa9cb3e68a78ac4a2e0ea0acf6844f", before
        )
        document = maintenance.validate_base_cohort_bytes(raw)
        original = copy.deepcopy(document)
        release.validate_release_publications(document)
        proof_manifest.validate_declared_currentness(document)
        self.assertEqual("stable_cohort_verified", release.publication_state(document))
        self.assertEqual(original, document)
        with self.assertRaisesRegex(
            maintenance.PlatformMaintenanceContractError, "frozen Q"
        ):
            maintenance.validate_base_cohort_bytes(raw + b" ")

    def test_original_r1_validator_never_accepts_r2(self) -> None:
        platform.validate_v0_1_5_publication_receipt(pending_receipt())
        value = revision_receipt()["publication"]
        with self.assertRaises(platform.PlatformV015PublicationContractError):
            platform.validate_v0_1_5_publication_receipt(value)

    def test_only_pending_then_verified_and_exact_idempotence(self) -> None:
        pending = revision_receipt()
        verified = revision_receipt(verified=True)
        maintenance.validate_transition(None, pending)
        maintenance.validate_transition(pending, verified)
        maintenance.validate_transition(verified, copy.deepcopy(verified))
        for before, after in ((None, verified), (verified, pending), (verified, None)):
            with self.subTest(before=before is None, after=after is None):
                with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                    maintenance.validate_transition(before, after)

    def test_wrong_anchor_source_revision_and_partial_receipt_are_rejected(
        self,
    ) -> None:
        valid = revision_receipt()
        mutations = (
            lambda value: value["base_cohort"].update(cohort_commit="0" * 40),
            lambda value: value["publication"]["identity"].update(
                distribution_revision="r1"
            ),
            lambda value: value["publication"]["observation"]["source"].update(
                tag_commit=maintenance.BASE_TAG_COMMIT
            ),
            lambda value: value["publication"]["observation"].pop(
                "candidate_attestation"
            ),
            lambda value: value["publication"]["observation"]["release_candidate"][
                "assets"
            ].pop(),
            lambda value: value.update(status="published_verified"),
        )
        for mutation in mutations:
            value = copy.deepcopy(valid)
            mutation(value)
            with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                maintenance.publication(value)

    def test_each_agp_consumer_has_exact_source_aar_tests_and_independent_run(
        self,
    ) -> None:
        valid = revision_receipt()
        mutations = (
            lambda consumers: consumers.pop("agp_minimal_release"),
            lambda consumers: consumers["agp_minimal_release"]["projection"].update(
                run_id=consumers["agp_full_release"]["projection"]["run_id"]
            ),
            lambda consumers: consumers["agp_full_release"]["projection"].update(
                aar_sha256="0" * 64
            ),
            lambda consumers: consumers["agp_full_release"]["projection"].update(
                source_commit="0" * 40
            ),
            lambda consumers: consumers["agp_full_release"]["projection"].update(
                source_tree_sha256="0" * 64
            ),
            lambda consumers: consumers["agp_full_release"]["projection"].update(
                passed_tests=[]
            ),
            lambda consumers: consumers["agp_full_release"].update(
                proof_path="../agp_full_release/proof.json"
            ),
        )
        for mutation in mutations:
            value = copy.deepcopy(valid)
            consumers = value["publication"]["observation"]["release_candidate"][
                "android_runtime_evidence"
            ]["agp_consumers"]
            mutation(consumers)
            with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                maintenance.publication(value)

    def test_promotion_cannot_swap_a_second_valid_agp_run(self) -> None:
        pending = revision_receipt()
        verified = revision_receipt(verified=True)
        observation = verified["publication"]["observation"]
        for runtime in (
            observation["release_candidate"]["android_runtime_evidence"],
            observation["android_runtime_evidence"],
        ):
            runtime["agp_consumers"]["agp_minimal_release"]["projection"].update(
                run_id="c" * 32,
                proof_sha256="c" * 64,
            )
        maintenance.publication(verified)
        with self.assertRaises(maintenance.PlatformMaintenanceContractError):
            maintenance.validate_transition(pending, verified)

    def test_maintenance_requires_original_and_all_new_tag_protection(self) -> None:
        ruleset = github_fixtures.GitHubReleaseObservationTests.stable_tag_ruleset()
        refs = ruleset["conditions"]["ref_name"]["include"]
        additions = (
            "refs/tags/abi2-platforms-v0.1.5-r2",
            "refs/tags/v0.1.5-verified-cohort",
            "refs/tags/abi2-platforms-v0.1.5-r2-verified",
        )
        refs.extend(additions)
        listing = canonical_json_bytes([{"id": 42}])
        github.parse_stable_tag_rulesets(
            listing, {42: canonical_json_bytes(ruleset)}, profile=PROFILE
        )
        for missing in (*additions, "refs/tags/v0.1.5"):
            changed = copy.deepcopy(ruleset)
            changed["conditions"]["ref_name"]["include"].remove(missing)
            with self.subTest(missing=missing):
                with self.assertRaises(github.GitHubReleaseObservationError):
                    github.parse_stable_tag_rulesets(
                        listing, {42: canonical_json_bytes(changed)}, profile=PROFILE
                    )

    def test_explicit_proxy_covers_original_and_revision_tags_in_both_composites(
        self,
    ) -> None:
        plan = maintenance_plan()
        proxy = "http://127.0.0.1:7890"
        source = {"GH_TOKEN": "fixture-maintenance-token"}
        protection = github.StableTagProtectionObservation(
            repository=publication.REPOSITORY,
            ruleset_ids=(42,),
            tag_refs=github.STABLE_TAG_REFS + (PROFILE.release_ref,),
            observation_sha256="a" * 64,
        )
        original = github.StableTagStateObservation(
            repository=publication.REPOSITORY,
            state="exact",
            tag_refs=github.STABLE_TAG_REFS,
            tag_objects=(
                maintenance.BASE_APPLE_TAG_OBJECT,
                maintenance.BASE_PLATFORM_TAG_OBJECT,
            ),
            commit=maintenance.BASE_TAG_COMMIT,
            tree=maintenance.BASE_TAG_TREE,
            observation_sha256="b" * 64,
        )
        revision = dataclasses.replace(
            original,
            tag_refs=(PROFILE.release_ref,),
            tag_objects=(plan.platform.tag_object,),
            commit=plan.tag_commit,
            tree=plan.tag_tree,
            observation_sha256="c" * 64,
        )
        with (
            mock.patch.object(
                github, "sample_stable_tag_protection_once", return_value=protection
            ) as protected,
            mock.patch.object(
                github, "sample_stable_tag_state_once", return_value=original
            ) as stable,
            mock.patch.object(
                github,
                "sample_platform_maintenance_tag_state_once",
                return_value=revision,
            ) as revised,
            mock.patch.object(
                github,
                "sample_mutable_release_transaction_once",
                return_value=maintenance_snapshot(plan, 0).releases,
            ) as releases,
        ):
            observed = publication.observe_remote_transaction(
                plan, source_environment=source, http_connect_proxy=proxy
            )
        self.assertEqual(0, publication.classify_remote_state(plan, observed).index)
        for sampler, count in (
            (protected, 4),
            (stable, 4),
            (revised, 4),
            (releases, 2),
        ):
            self.assertEqual(count, sampler.call_count)
            for call in sampler.call_args_list:
                self.assertEqual(proxy, call.kwargs["http_connect_proxy"])
                self.assertEqual(source, call.kwargs["source_environment"])
        self.assertEqual(
            maintenance.BASE_TAG_COMMIT, stable.call_args.kwargs["expected_commit"]
        )
        self.assertEqual(plan.tag_commit, revised.call_args.kwargs["expected_commit"])

    def test_new_annotated_tag_cannot_alias_original_or_change_object_commit_tree(
        self,
    ) -> None:
        fixture = github_fixtures.GitHubReleaseObservationTests
        ref = "refs/tags/abi2-platforms-v0.1.5-r2"
        tag_object, commit, tree = "6" * 40, "7" * 40, "8" * 40
        records = [
            [fixture.stable_tag_reference(ref, tag_object)],
            fixture.stable_annotated_tag(ref, tag_object, commit),
            fixture.stable_commit(commit, tree),
        ]

        def parse(values):
            return github.parse_platform_maintenance_tag_state(
                *(canonical_json_bytes(value) for value in values),
                expected_tag_object=tag_object,
                expected_commit=commit,
                expected_tree=tree,
            )

        self.assertEqual((ref,), parse(records).tag_refs)
        mutations = (
            lambda values: values[0][0].update(ref="refs/tags/abi2-platforms-v0.1.5"),
            lambda values: values[0][0]["object"].update(sha="0" * 40),
            lambda values: values[1]["object"].update(sha="0" * 40),
            lambda values: values[1].update(tag="abi2-platforms-v0.1.5"),
            lambda values: values[2]["tree"].update(sha="0" * 40),
        )
        for mutation in mutations:
            changed = copy.deepcopy(records)
            mutation(changed)
            with self.assertRaises(github.GitHubReleaseObservationError):
                parse(changed)


class PlatformMaintenanceCacheTests(unittest.TestCase):
    def test_retained_r1_and_r2_caches_select_exact_profile_and_unknown_history_fails(
        self,
    ) -> None:
        fixture = distribution_fixtures.PlatformDistributionTests()
        fixture.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        r1_path, _r1_digest, _r1_release, r1 = fixture._assemble_candidate_transaction(
            "r1"
        )
        r2_path, _r2_digest, _r2_release, r2 = fixture._assemble_candidate_transaction(
            "r2"
        )
        # This test exercises cache admission and byte preservation. The existing
        # distribution fixture supplies its package/deep-verifier seam; the
        # complete AGP archive is tested separately by the bundle verifier.
        r2["identity"] = PROFILE.identity()
        r2["schema_version"] = 2
        runtime = r2["android_runtime_evidence"]
        runtime["bundle_schema"] = 3
        runtime["agp_consumers"] = copy.deepcopy(
            revision_receipt()["publication"]["observation"]["release_candidate"][
                "android_runtime_evidence"
            ]["agp_consumers"]
        )
        for consumer in runtime["agp_consumers"].values():
            consumer["projection"].update(
                source_commit=r2["source"]["git_commit"],
                source_tree_sha256=r2["source"]["canonical_source_tree_sha256"],
                aar_sha256=runtime["tested_aar_sha256"],
                aar_manifest_sha256=runtime["tested_aar_manifest_sha256"],
            )
        r2_path.write_bytes(distribution.canonical_json(r2))
        before = {path: path.read_bytes() for path in (r1_path, r2_path)}
        source = {
            "canonical_source_tree_sha256": r1["source"][
                "canonical_source_tree_sha256"
            ],
            "tag_commit": r1["source"]["git_commit"],
            "tag_tree": r1["source"]["git_tree"],
            "source_date_epoch": r1["source"]["source_date_epoch"],
        }
        with mock.patch.object(
            distribution, "PLATFORM_RELEASE_CANDIDATE_ROOT", r1_path.parent.parent
        ):
            for profile, receipt in (
                (publication.PlatformReleaseProfile.STABLE, r1),
                (PROFILE, r2),
            ):
                projection = {
                    key: receipt[key]
                    for key in (
                        "android_runtime_evidence",
                        "assets",
                        "checksums_sha256",
                        "platform_distribution_sha256",
                    )
                }
                selected = distribution.find_selected_release_candidate_bundle(
                    projection, source, profile=profile
                )
                self.assertEqual(receipt, selected.receipt)
            self.assertEqual(before, {path: path.read_bytes() for path in before})
            unknown = copy.deepcopy(r1)
            unknown["schema_version"] = 9
            r1_path.write_bytes(distribution.canonical_json(unknown))
            with self.assertRaisesRegex(
                distribution.PlatformDistributionError, "retained platform candidate"
            ):
                distribution.find_selected_release_candidate_bundle(
                    projection, source, profile=PROFILE
                )
            r1_path.write_bytes(before[r1_path])
            with self.assertRaises(distribution.PlatformDistributionError):
                distribution.load_release_candidate_bundle(r2_path)


class PlatformMaintenanceFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        # Compose the existing committed-results harness without rediscovering
        # its unrelated three-domain tests through TestCase inheritance.
        self.fixture = finalizer_fixtures.ReleaseReceiptFinalizerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.addCleanup(self.fixture.doCleanups)
        q_bytes = (
            pathlib.Path(__file__).parent / "fixtures/published-v0.1.5-results.json"
        ).read_bytes()
        blob = self._git_object(("hash-object", "-w", "--stdin"), q_bytes)
        tree = self._git_object(
            ("mktree",), f"100644 blob {blob}\tresults.json\n".encode()
        )
        root_tree = self._git_object(
            ("mktree",), f"040000 tree {tree}\tartifact\n".encode()
        )
        q_commit = self._git_object(("commit-tree", root_tree), b"Frozen Q fixture\n")
        self.enterContext(
            mock.patch.object(maintenance_source, "BASE_COHORT_COMMIT", q_commit)
        )
        # The local Git fixture has its own product commit; the immutable receipt's
        # original-cohort comparison must continue to use the published constant.
        self.enterContext(
            mock.patch.object(
                maintenance_source,
                "product_contract",
                side_effect=lambda profile: (
                    dataclasses.replace(
                        maintenance.product_contract(profile),
                        product_commit=self.fixture.source_commit,
                    )
                    if profile is PROFILE
                    else maintenance.product_contract(profile)
                ),
            )
        )

    def _git_object(self, arguments: tuple[str, ...], data: bytes) -> str:
        return (
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "user.name=Q-Periapt Test",
                    "-c",
                    "user.email=q-periapt-test@example.invalid",
                    "-C",
                    str(self.fixture.root),
                    *arguments,
                ],
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            .stdout.decode("ascii")
            .strip()
        )

    def _receipt(
        self,
        *,
        verified: bool,
        release_profile: publication.PlatformReleaseProfile = PROFILE,
    ) -> pathlib.Path:
        value = revision_receipt(verified=verified, release_profile=release_profile)
        inner = release_fixtures._rebind_platform(
            value["publication"], self.fixture._source_identity()
        )
        observation = inner["observation"]
        runtimes = [observation["release_candidate"]["android_runtime_evidence"]]
        if verified:
            runtimes.append(observation["android_runtime_evidence"])
        for runtime in runtimes:
            for consumer in runtime["agp_consumers"].values():
                consumer["projection"].update(
                    source_commit=self.fixture.results_commit,
                    source_tree_sha256=self.fixture.source_digest,
                )
        return self.fixture._receipt_path(
            self.fixture.platform_root,
            collector.receipt_name(release_profile),
            maintenance.wrap_publication(inner, profile=release_profile),
            "maintenance-verified" if verified else "maintenance-pending",
        )

    def _install(
        self,
        *,
        verified: bool,
        release_profile: publication.PlatformReleaseProfile = PROFILE,
    ) -> tuple[str, str, pathlib.Path]:
        previous_commit = self.fixture._commit()
        previous_sha256 = self.fixture._current_sha256()
        receipt = self._receipt(verified=verified, release_profile=release_profile)
        current, committed = finalizer.assemble_maintenance_results(
            previous_sha256, receipt_path=receipt, profile=release_profile
        )
        self.assertEqual(previous_commit, committed.commit)
        for key in current.keys() - {"release_publications"}:
            self.assertEqual(committed.manifest[key], current[key])
        retained = {
            key: value
            for key, value in current["release_publications"].items()
            if key != release_profile.publication_key
        }
        self.assertEqual(
            {
                key: value
                for key, value in committed.manifest["release_publications"].items()
                if key != release_profile.publication_key
            },
            retained,
        )
        self.fixture._write_results(current)
        self.fixture._git("add", "artifact/results.json")
        self.fixture._git("commit", "-qm", "record platform maintenance")
        commit, status = finalizer.verify_installed_results(
            self.fixture._current_sha256(),
            expected_parent_commit=previous_commit,
            expected_parent_results_sha256=previous_sha256,
        )
        self.assertEqual(self.fixture._commit(), commit)
        self.assertEqual(
            (
                "platform_maintenance_verified"
                if verified
                else "platform_maintenance_pending"
            ),
            status,
        )
        return commit, self.fixture._current_sha256(), receipt

    def test_real_results_only_pending_verified_and_read_only_final_verification(
        self,
    ) -> None:
        _pending, digest, pending_receipt_path = self._install(verified=False)
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "complete verified receipt"
        ):
            finalizer.run(
                argparse.Namespace(
                    command="verify-maintenance",
                    expected_results_sha256=digest,
                    platform_receipt=pending_receipt_path,
                    profile=PROFILE.value,
                )
            )
        _verified, digest, receipt = self._install(verified=True)
        before = self.fixture.results.read_bytes()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            finalizer.run(
                argparse.Namespace(
                    command="verify-maintenance",
                    expected_results_sha256=digest,
                    platform_receipt=receipt,
                    profile=PROFILE.value,
                )
            )
        self.assertIn("PLATFORM_MAINTENANCE_RESULTS_VERIFY_PASS", output.getvalue())
        self.assertEqual(before, self.fixture.results.read_bytes())

    def test_direct_verified_and_results_with_wrong_source_are_rejected(self) -> None:
        receipt = self._receipt(verified=True)
        with self.assertRaises(finalizer.ReleaseReceiptFinalizerError):
            finalizer.assemble_maintenance_results(
                self.fixture._current_sha256(), receipt_path=receipt
            )
        pending = self._receipt(verified=False)
        value = json.loads(pending.read_bytes())
        value["publication"]["observation"]["source"]["source_parent_commit"] = "0" * 40
        pending.write_bytes(canonical_json_bytes(value))
        with self.assertRaises(finalizer.ReleaseReceiptFinalizerError):
            finalizer.assemble_maintenance_results(
                self.fixture._current_sha256(), receipt_path=pending
            )

    def test_non_results_source_change_cannot_be_finalized(self) -> None:
        receipt = self._receipt(verified=False)
        (self.fixture.root / "source.txt").write_text("changed source\n")
        self.fixture._git("add", "source.txt")
        self.fixture._git("commit", "-qm", "change source after release identity")
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "Git source binding"
        ):
            finalizer.assemble_maintenance_results(
                self.fixture._current_sha256(), receipt_path=receipt
            )

    def test_local_q_object_with_different_results_bytes_is_rejected(self) -> None:
        receipt = self._receipt(verified=False)
        before = self.fixture.results.read_bytes()
        with mock.patch.object(
            maintenance_source, "BASE_COHORT_COMMIT", self.fixture.results_commit
        ):
            with self.assertRaisesRegex(
                finalizer.ReleaseReceiptFinalizerError, "frozen Q"
            ):
                finalizer.assemble_maintenance_results(
                    self.fixture._current_sha256(), receipt_path=receipt
                )
        self.assertEqual(before, self.fixture.results.read_bytes())

    def test_retained_results_and_historical_publications_cannot_change(self) -> None:
        original = json.loads(self.fixture.results.read_bytes())
        pending, _committed = finalizer.assemble_maintenance_results(
            self.fixture._current_sha256(), receipt_path=self._receipt(verified=False)
        )
        for section in ("swift_xcframework", "provenance", "rust_publish"):
            changed = copy.deepcopy(pending)
            changed[section] = {}
            with self.assertRaises(finalizer.ReleaseReceiptFinalizerError):
                finalizer._assert_only_maintenance_mutations(original, changed)
        changed = copy.deepcopy(pending)
        old_key = next(iter(original["release_publications"]))
        changed["release_publications"][old_key] = {}
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "retained publication"
        ):
            finalizer._assert_only_maintenance_mutations(original, changed)

    def test_local_git_source_guard_accepts_packaging_and_rejects_product_changes(
        self,
    ) -> None:
        maintenance_source.verify_product_source(
            self.fixture.root, self.fixture.results_commit
        )
        (self.fixture.root / "artifact/packaging.txt").write_text("packaging\n")
        self.fixture._git("add", "artifact/packaging.txt")
        self.fixture._git("commit", "-qm", "update packaging")
        maintenance_source.verify_product_source(
            self.fixture.root, self.fixture._commit()
        )
        (self.fixture.root / "Cargo.toml").write_text("[workspace]\n")
        self.fixture._git("add", "Cargo.toml")
        self.fixture._git("commit", "-qm", "change published product")
        with self.assertRaisesRegex(
            maintenance.PlatformMaintenanceContractError, "frozen product"
        ):
            maintenance_source.verify_product_source(
                self.fixture.root, self.fixture._commit()
            )
        with mock.patch.object(maintenance_source, "BASE_COHORT_COMMIT", "0" * 40):
            with self.assertRaisesRegex(
                maintenance.PlatformMaintenanceContractError, "unavailable locally"
            ):
                maintenance_source.verify_product_source(
                    self.fixture.root, self.fixture.results_commit
                )


class PlatformMaintenanceTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        stable_fixtures.StableGitHubPublicationTests.setUp(self)
        self.plan = maintenance_plan()
        self.account_root = self.root
        self.root = self.account_root.with_name("github-platform-v0.1.5-r2")
        self.account_root.rename(self.root)
        self.account_root.mkdir(mode=0o700)
        lock = self.account_root / publication.LOCK_LEAF
        lock.write_bytes(b"")
        lock.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @contextlib.contextmanager
    def _publisher_patches(self):
        def root_for(profile=publication.PlatformReleaseProfile.STABLE):
            return self.root if profile is PROFILE else self.account_root

        with (
            mock.patch.object(publication, "expected_state_root", side_effect=root_for),
            mock.patch.object(publication, "_registered_worktrees", return_value=()),
            mock.patch.object(
                publication, "_load_prepared_plan", return_value=self.plan
            ),
            mock.patch.object(publication, "verify_local_plan", return_value=None),
        ):
            yield

    def _replace_account_authority(self, *, directory: bool):
        original = (
            self.account_root
            if directory
            else self.account_root / publication.LOCK_LEAF
        )
        preserved = self.account_root.with_name("retained-account-authority")
        original.rename(preserved)
        if directory:
            original.mkdir(mode=0o700)
            replacement = original / publication.LOCK_LEAF
        else:
            replacement = original
        replacement.write_bytes(b"")
        replacement.chmod(0o600)

        def restore():
            replacement.unlink()
            if directory:
                original.rmdir()
            preserved.rename(original)

        return restore

    def _publish(self, remote: MaintenanceRemote) -> publication.PublicationStatus:
        return publication.publish_plan(
            profile=PROFILE,
            execute_real_github_mutation=True,
            expected_plan_sha256=self.plan.sha256(),
            expected_results_sha256=self.plan.results_sha256,
            draft_barrier_ack="I_ACKNOWLEDGE_PLATFORM_REVISION_DRAFT_BEFORE_UPLOAD",
            publication_order_ack="I_ACKNOWLEDGE_ORIGINAL_RELEASES_REMAIN_UNCHANGED",
            state_root=self.root,
            observer=remote.observe,
            mutator=remote.mutate,
        )

    def test_plan_is_explicit_and_contains_no_apple_requests(self) -> None:
        parsed = publication.parse_plan(self.plan.document())
        self.assertEqual(self.plan, parsed)
        self.assertEqual(9, parsed.action_count)
        self.assertEqual(
            list(EXPECTED_ACTIONS),
            [a.action_id for a in publication.action_sequence(parsed)],
        )
        self.assertIsNone(parsed.apple.create_request)
        self.assertIsNone(parsed.apple.publish_request)
        self.assertEqual(
            {"create-platform.json", "publish-platform.json"},
            set(publication._request_payloads(parsed)),
        )
        for index in range(10):
            self.assertEqual(
                index,
                publication.classify_remote_state(
                    parsed, maintenance_snapshot(parsed, index)
                ).index,
            )

    def test_wrong_anchor_and_apple_mutation_authority_are_rejected(self) -> None:
        value = self.plan.document()
        value["base_cohort"]["platform_release_id"] += 1
        with self.assertRaises(publication.StableGitHubPublicationError):
            publication.parse_plan(value)
        with mock.patch.object(github, "select_github_cli") as select:
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError, "exact publication profile"
            ):
                publication.execute_production_mutation(
                    None,
                    self.plan,
                    publication.MutationAction(
                        0, "create-apple-draft", "create", "apple"
                    ),
                    maintenance_snapshot(self.plan, 0),
                )
            select.assert_not_called()

    def test_shared_journal_completes_only_nine_platform_mutations(self) -> None:
        remote = MaintenanceRemote(self.plan, self.root / publication.JOURNAL_DIRECTORY)
        with self._publisher_patches():
            status = self._publish(remote)
            repeated = self._publish(remote)
        self.assertTrue(status.complete)
        self.assertTrue(repeated.complete)
        self.assertEqual(9, status.applied_actions)
        self.assertEqual(list(EXPECTED_ACTIONS), remote.mutations)

    def test_offline_prepare_stages_only_seven_platform_assets_and_two_requests(
        self,
    ) -> None:
        self.root.rename(self.root.with_name("retained-fixture"))
        account_lock = self.account_root / publication.LOCK_LEAF
        account_inode = account_lock.stat().st_ino

        def stage_platform(_candidate, _source, **kwargs):
            self.assertIs(PROFILE, kwargs["profile"])
            for index, asset in enumerate(self.plan.platform.assets):
                publication.write_private_bytes_noreplace_at(
                    kwargs["staging_directory_fd"],
                    kwargs["staging_leaves"][asset.name],
                    bytes([31 + index]) * asset.size,
                    label=f"fixture platform asset {asset.name}",
                    maximum=asset.size,
                )
            return object()

        with (
            self._publisher_patches(),
            mock.patch.object(
                publication,
                "build_plan_from_pending_results",
                return_value=(
                    self.plan,
                    (),
                    {"candidate": "P2-selected"},
                    {"source": "P2-selected"},
                ),
            ),
            mock.patch.object(
                publication.platform_distribution,
                "find_selected_release_candidate_bundle",
                side_effect=stage_platform,
            ),
            mock.patch.object(
                github,
                "github_cli_environment",
                side_effect=AssertionError("offline prepare read credentials"),
            ) as credentials,
            mock.patch.object(
                publication,
                "observe_remote_transaction",
                side_effect=AssertionError("offline prepare accessed GitHub"),
            ) as observer,
        ):
            result = publication.prepare_plan(
                self.plan.results_sha256, state_root=self.root, profile=PROFILE
            )
        self.assertEqual(self.plan, result)
        credentials.assert_not_called()
        observer.assert_not_called()
        staged = self.root / publication.STAGING_DIRECTORY
        expected = {
            asset.staging_leaf: asset.sha256 for asset in self.plan.platform.assets
        }
        self.assertEqual(set(expected), {path.name for path in staged.iterdir()})
        for leaf, digest in expected.items():
            self.assertEqual(
                digest, hashlib.sha256((staged / leaf).read_bytes()).hexdigest()
            )
        self.assertEqual(
            {"create-platform.json", "publish-platform.json"},
            {
                path.name
                for path in (self.root / publication.REQUEST_DIRECTORY).iterdir()
            },
        )
        self.assertEqual(account_inode, account_lock.stat().st_ino)
        self.assertEqual(b"", account_lock.read_bytes())

    def test_unknown_after_send_preserves_intent_and_does_not_resend(self) -> None:
        remote = MaintenanceRemote(self.plan, self.root / publication.JOURNAL_DIRECTORY)
        remote.fail_after_effect = True
        with self._publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self._publish(remote)
            journal = self.root / publication.JOURNAL_DIRECTORY
            original = (journal / "000000-intent.json").read_bytes()
            self.assertFalse((journal / "000000-outcome.json").exists())
            self.assertEqual(["create-platform-draft"], remote.mutations)
            completed = self._publish(remote)
            self.assertTrue(completed.complete)
            self.assertEqual(original, (journal / "000000-intent.json").read_bytes())
            self.assertEqual(1, remote.mutations.count("create-platform-draft"))

    def _reject_changed_account_before_mutation(self, *, directory: bool) -> None:
        remote = MaintenanceRemote(self.plan, self.root / publication.JOURNAL_DIRECTORY)
        original_observe = remote.observe
        restorations = []

        def observe(plan):
            snapshot = original_observe(plan)
            if not restorations:
                restorations.append(
                    self._replace_account_authority(directory=directory)
                )
            return snapshot

        remote.observe = observe
        try:
            with self._publisher_patches():
                with self.assertRaises(
                    publication.StableGitHubPublicationBoundaryIntegrityError
                ):
                    self._publish(remote)
        finally:
            for restore in restorations:
                restore()
        self.assertEqual([], remote.mutations)
        self.assertEqual(
            [], list((self.root / publication.JOURNAL_DIRECTORY).iterdir())
        )

    def test_replaced_account_lock_inode_is_rejected_before_next_mutation(self) -> None:
        self._reject_changed_account_before_mutation(directory=False)

    def test_replaced_account_directory_is_rejected_before_next_mutation(self) -> None:
        self._reject_changed_account_before_mutation(directory=True)

    def test_original_and_revision_lanes_are_mutually_exclusive_in_both_directions(
        self,
    ) -> None:
        account_inode = (self.account_root / publication.LOCK_LEAF).stat().st_ino
        revision_inode = (self.root / publication.LOCK_LEAF).stat().st_ino
        with self._publisher_patches():
            for held, blocked in (
                (self.account_root, self.root),
                (self.root, self.account_root),
            ):
                with publication.publication_lock(
                    held, allow_create=False
                ) as authority:
                    self.assertEqual(held == self.root, authority.account is not None)
                    with self.assertRaises(publication.StableGitHubPublicationLockHeld):
                        with publication.publication_lock(blocked, allow_create=False):
                            self.fail(
                                "two publication lanes acquired separate authority"
                            )
        self.assertEqual(
            account_inode, (self.account_root / publication.LOCK_LEAF).stat().st_ino
        )
        self.assertEqual(
            revision_inode, (self.root / publication.LOCK_LEAF).stat().st_ino
        )

    def test_account_change_after_send_preserves_unknown_and_prevents_retry(
        self,
    ) -> None:
        journal = self.root / publication.JOURNAL_DIRECTORY
        remote = MaintenanceRemote(self.plan, journal)
        original_mutate = remote.mutate
        restorations = []

        def mutate(plan, action, before):
            original_mutate(plan, action, before)
            restorations.append(self._replace_account_authority(directory=False))
            raise github.GitHubCliExecutionError(
                "ambiguous response after account authority changed",
                error_kind="timeout",
                returncode=None,
            )

        remote.mutate = mutate
        try:
            with self._publisher_patches():
                with self.assertRaises(
                    publication.StableGitHubPublicationBoundaryIntegrityError
                ) as failure:
                    self._publish(remote)
        finally:
            for restore in restorations:
                restore()
        intent = (journal / "000000-intent.json").read_bytes()
        self.assertEqual("timeout", failure.exception.error_kind)
        self.assertFalse((journal / "000000-outcome.json").exists())
        self.assertFalse((journal / "000000-reconciliation.json").exists())
        self.assertEqual(["create-platform-draft"], remote.mutations)
        with self._publisher_patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self._publish(remote)
        self.assertEqual(intent, (journal / "000000-intent.json").read_bytes())
        self.assertEqual(["create-platform-draft"], remote.mutations)


def _git(root: pathlib.Path, *arguments: str, umask: int = -1) -> str:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "user.name=Q-Periapt Test",
            "-c",
            "user.email=q-periapt-test@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(root),
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        umask=umask,
    )
    return completed.stdout.decode("utf-8").strip()


def _write(path: pathlib.Path, data: bytes, mode: int) -> None:
    path.write_bytes(data)
    path.chmod(mode)


class _MaintenanceRepository:
    """Reuse the full manifest fixture, real S/R/P2 commits and real annotated tags.

    Payloads and attestation projections are fixture data. Their byte inventory,
    currentness contracts, Git ancestry, cache selection and publication staging
    execute the production validators without replacements.
    """

    def __init__(self, case: unittest.TestCase) -> None:
        history = PlatformMaintenanceFinalizerTests()
        history.setUp()
        case.addCleanup(history.doCleanups)
        self.history = history
        self.fixture = history.fixture
        self.root = self.fixture.root
        self.results = self.fixture.results

        _git(
            self.root,
            "tag",
            "-a",
            "v0.1.5",
            self.fixture.source_commit,
            "-m",
            "original release",
        )
        _git(
            self.root,
            "tag",
            "-a",
            PROFILE.release_tag,
            self.fixture.results_commit,
            "-m",
            "platform revision",
        )
        case.enterContext(
            mock.patch.multiple(
                maintenance,
                BASE_TAG_COMMIT=self.fixture.source_commit,
                BASE_TAG_TREE=_git(
                    self.root, "rev-parse", f"{self.fixture.source_commit}^{{tree}}"
                ),
                BASE_APPLE_TAG_OBJECT=_git(
                    self.root, "rev-parse", "refs/tags/v0.1.5^{tag}"
                ),
            )
        )
        self.receipt_path = history._receipt(verified=False)
        receipt = json.loads(self.receipt_path.read_bytes())
        observation = receipt["publication"]["observation"]
        observation["source"]["tag_object"] = _git(
            self.root, "rev-parse", f"refs/tags/{PROFILE.release_tag}^{{tag}}"
        )
        self.payloads = {
            name: f"publication fixture bytes for {name}\n".encode("ascii")
            for name in platform.PUBLIC_ASSET_NAMES
        }
        digests = {
            name: hashlib.sha256(data).hexdigest()
            for name, data in self.payloads.items()
        }
        candidate = observation["release_candidate"]
        for asset in candidate["assets"]:
            name = asset["name"]
            asset.update(bytes=len(self.payloads[name]), sha256=digests[name])
        candidate["checksums_sha256"] = digests[platform.RELEASE_SUMS]
        candidate["platform_distribution_sha256"] = digests[platform.RELEASE_MANIFEST]
        runtime = candidate["android_runtime_evidence"]
        runtime.update(
            bundle_sha256=digests[platform.ANDROID_RUNTIME_BUNDLE],
            tested_aar_sha256=digests[platform.ANDROID_AAR],
            tested_aar_manifest_sha256=digests[platform.ANDROID_MANIFEST],
        )
        for consumer in runtime["agp_consumers"].values():
            consumer["projection"].update(
                aar_sha256=digests[platform.ANDROID_AAR],
                aar_manifest_sha256=digests[platform.ANDROID_MANIFEST],
            )
        for subject in observation["candidate_attestation"]["subjects"]:
            if subject["name"] in digests:
                subject["digest"]["sha256"] = digests[subject["name"]]
        source = observation["source"]
        self.cache_receipt = {
            **copy.deepcopy(candidate),
            "schema_version": PROFILE.candidate_receipt_schema,
            "kind": distribution_contract.PLATFORM_RELEASE_CANDIDATE_KIND,
            "identity": PROFILE.identity(),
            "source": {
                "canonical_source_tree_sha256": source["canonical_source_tree_sha256"],
                "git_commit": source["tag_commit"],
                "git_dirty": False,
                "git_tree": source["tag_tree"],
                "source_date_epoch": source["source_date_epoch"],
            },
        }
        distribution_contract.validate_release_candidate_receipt(
            self.cache_receipt, profile=PROFILE
        )
        self.cache_root = self.root / "target" / "abi2-platform-release-candidates"
        self.cache_root.mkdir(mode=0o700)
        transaction = self.cache_root / "transaction.root-regression"
        transaction.mkdir(mode=0o700)
        payload_root = transaction / distribution.PLATFORM_RELEASE_DIRECTORY_NAME
        payload_root.mkdir(mode=0o755)
        payload_root.chmod(0o755)
        for name, data in self.payloads.items():
            _write(payload_root / name, data, 0o644)
        cache_bytes = distribution.canonical_json(self.cache_receipt)
        _write(
            transaction / distribution.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME,
            cache_bytes,
            0o600,
        )
        observation["assembly_receipt_sha256"] = hashlib.sha256(cache_bytes).hexdigest()
        maintenance.publication(receipt)
        _write(self.receipt_path, canonical_json_bytes(receipt), 0o600)
        current, previous = finalizer.assemble_maintenance_results(
            self.fixture._current_sha256(), receipt_path=self.receipt_path
        )
        case.assertEqual(self.fixture.results_commit, previous.commit)
        self.fixture._write_results(current)
        _git(self.root, "add", "artifact/results.json")
        _git(self.root, "commit", "-qm", "record pending platform revision")
        self.pending_commit = _git(self.root, "rev-parse", "HEAD")
        self.digest = self.fixture._current_sha256()
        proof_manifest.validate_declared_currentness(current)
        release.validate_stable_source_currentness(current)
        case.assertEqual(
            release.PUBLICATION_STATE_SOURCE, release.publication_state(current)
        )

        tool = github.GitHubCliIdentity(
            path="/usr/bin/gh",
            device=1,
            inode=2,
            mode=0o755,
            uid=os.geteuid(),
            link_count=1,
            size=1,
            sha256=github.GITHUB_CLI_SHA256,
        )
        case.enterContext(
            mock.patch.object(github, "select_github_cli", return_value=tool)
        )
        home = tempfile.TemporaryDirectory()
        case.addCleanup(home.cleanup)
        self.home = pathlib.Path(home.name).resolve()
        case.enterContext(
            mock.patch.object(publication, "_account_home", return_value=self.home)
        )
        self.account_root = publication.expected_state_root()
        self.state_root = publication.expected_state_root(PROFILE)
        self.account_root.mkdir(mode=0o700, parents=True)
        for parent in (self.account_root.parent.parent, self.account_root.parent):
            parent.chmod(0o700)
        _write(self.account_root / publication.LOCK_LEAF, b"", 0o600)

    def prepare(self) -> publication.PublicationPlan:
        return publication.prepare_plan(
            self.digest, profile=PROFILE, repository_root=self.root
        )


class PublicationRepositoryRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = _MaintenanceRepository(self)

    def test_real_r_to_p2_prepare_and_verify_preserve_currentness_and_exact_bytes(
        self,
    ) -> None:
        selected = self.repository
        before = selected.results.read_bytes()
        plan = selected.prepare()
        publication.verify_local_plan(
            selected.state_root, plan, repository_root=selected.root
        )
        self.assertEqual(selected.pending_commit, plan.pending_commit)
        self.assertEqual(selected.fixture.results_commit, plan.tag_commit)
        self.assertEqual(PROFILE, plan.profile)
        self.assertEqual(9, plan.action_count)
        self.assertIsNone(plan.apple.create_request)
        self.assertIsNone(plan.apple.publish_request)
        for asset in plan.platform.assets:
            staged = (
                selected.state_root / publication.STAGING_DIRECTORY / asset.staging_leaf
            )
            self.assertEqual(selected.payloads[asset.name], staged.read_bytes())
        self.assertEqual(before, selected.results.read_bytes())

    def test_cli_prepare_uses_explicit_checkout_without_changing_default_roots(
        self,
    ) -> None:
        selected = self.repository
        defaults = (
            publication.REPOSITORY_ROOT,
            finalizer.REPOSITORY_ROOT,
            finalizer.RESULTS_PATH,
        )
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            result = publication.main(
                [
                    "--repository-root",
                    str(selected.root),
                    "--profile",
                    PROFILE.value,
                    "prepare",
                    selected.digest,
                ]
            )
        self.assertEqual(0, result)
        self.assertIn("STABLE_GITHUB_PREPARED", output.getvalue())
        self.assertIn("actions=9 assets=7", output.getvalue())
        self.assertEqual(
            defaults,
            (
                publication.REPOSITORY_ROOT,
                finalizer.REPOSITORY_ROOT,
                finalizer.RESULTS_PATH,
            ),
        )

    def test_completed_prepare_and_status_do_not_require_disposable_candidate_cache(
        self,
    ) -> None:
        selected = self.repository
        plan = selected.prepare()
        selected.cache_root.rename(
            selected.cache_root.with_name("retained-candidate-cache")
        )
        self.assertEqual(plan, selected.prepare())
        status = publication.status_plan(
            repository_root=selected.root,
            state_root=selected.state_root,
            observer=lambda current: maintenance_snapshot(current, 0),
        )
        self.assertEqual(0, status.applied_actions)
        self.assertFalse(status.complete)

    def test_selected_cache_is_used_even_when_tool_default_cache_is_invalid(
        self,
    ) -> None:
        selected = self.repository
        decoy = selected.home / "invalid-tool-cache"
        decoy.mkdir(mode=0o700)
        _write(decoy / "unexpected", b"wrong cache\n", 0o600)
        with mock.patch.object(distribution, "PLATFORM_RELEASE_CANDIDATE_ROOT", decoy):
            plan = selected.prepare()
        self.assertEqual(selected.pending_commit, plan.pending_commit)
        self.assertEqual(b"wrong cache\n", (decoy / "unexpected").read_bytes())

    def test_selected_cache_failure_does_not_fall_back_to_tool_default_cache(
        self,
    ) -> None:
        selected = self.repository
        retained = selected.cache_root.with_name("retained-valid-cache")
        selected.cache_root.rename(retained)
        selected.cache_root.mkdir(mode=0o700)
        with mock.patch.object(
            distribution, "PLATFORM_RELEASE_CANDIDATE_ROOT", retained
        ):
            with self.assertRaises(distribution.PlatformDistributionError):
                selected.prepare()
        self.assertFalse((selected.state_root / publication.PLAN_LEAF).exists())

    def test_wrong_head_rejected_then_original_root_remains_usable_in_same_process(
        self,
    ) -> None:
        selected = self.repository
        plan = selected.prepare()
        other = selected.home / "other-checkout"
        _git(
            selected.home,
            "clone",
            "--no-hardlinks",
            str(selected.root),
            str(other),
            umask=0o077,
        )
        copied_results = other / "artifact" / "results.json"
        self.assertEqual(0o600, copied_results.stat().st_mode & 0o777)
        self.assertEqual(
            git_provenance.run_git_bytes(other, ["show", "HEAD:artifact/results.json"]),
            copied_results.read_bytes(),
        )
        copied_results.chmod(0o644)
        publication.verify_local_plan(selected.state_root, plan, repository_root=other)
        _git(other, "commit", "--allow-empty", "-qm", "unrelated successor")
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError, "pending results differ"
        ):
            publication.verify_local_plan(
                selected.state_root, plan, repository_root=other
            )
        publication.verify_local_plan(
            selected.state_root, plan, repository_root=selected.root
        )
        self.assertEqual(
            selected.pending_commit,
            finalizer.load_current_results(
                selected.digest, repository_root=selected.root
            ).commit,
        )

    def test_staged_and_unstaged_changes_cannot_authorize_publication(self) -> None:
        selected = self.repository
        plan = selected.prepare()
        before = selected.results.read_bytes()
        for staged in (False, True):
            with self.subTest(staged=staged):
                _write(selected.results, before + b"\n", 0o644)
                if staged:
                    _git(selected.root, "add", "artifact/results.json")
                with self.assertRaises(publication.StableGitHubPublicationError):
                    publication.verify_local_plan(
                        selected.state_root, plan, repository_root=selected.root
                    )
                _git(selected.root, "reset", "--hard", selected.pending_commit)
                selected.results.chmod(0o644)
        source = selected.root / "untracked-source.py"
        source.write_text("raise RuntimeError('untrusted input')\n")
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError, "clean committed checkout"
        ):
            publication.verify_local_plan(
                selected.state_root, plan, repository_root=selected.root
            )

    def test_committed_pending_child_with_source_change_is_rejected(self) -> None:
        selected = self.repository
        pending_bytes = selected.results.read_bytes()
        _git(selected.root, "reset", "--hard", selected.fixture.results_commit)
        _write(selected.results, pending_bytes, 0o644)
        (selected.root / "source.txt").write_text("changed source\n")
        _git(selected.root, "add", "artifact/results.json", "source.txt")
        _git(selected.root, "commit", "-qm", "change source with pending receipt")
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError, "results-only commits"
        ):
            selected.prepare()

    def test_stable_profile_rejects_maintenance_pending_manifest(self) -> None:
        selected = self.repository
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError, "pending cohort P"
        ):
            publication.build_plan_from_pending_results(
                selected.digest, repository_root=selected.root
            )

    def test_maintenance_rejects_a_valid_verified_revision(self) -> None:
        selected = self.repository
        manifest = json.loads(selected.results.read_bytes())
        verified_path = selected.history._receipt(verified=True)
        manifest["release_publications"][maintenance.PUBLICATION_KEY] = json.loads(
            verified_path.read_bytes()
        )
        proof_manifest.validate_declared_currentness(manifest)
        self.assertEqual(
            release.PUBLICATION_STATE_SOURCE, release.publication_state(manifest)
        )
        with self.assertRaisesRegex(
            publication.StableGitHubPublicationError, "own installed pending receipt"
        ):
            publication._require_pending_profile(manifest, PROFILE)

    def test_neither_profile_accepts_source_results_without_pending_receipt(
        self,
    ) -> None:
        selected = self.repository
        manifest = json.loads(
            _git(
                selected.root,
                "show",
                f"{selected.fixture.results_commit}:artifact/results.json",
            )
        )
        proof_manifest.validate_declared_currentness(manifest)
        for profile in publication.PlatformReleaseProfile:
            with self.subTest(profile=profile.value):
                with self.assertRaises(publication.StableGitHubPublicationError):
                    publication._require_pending_profile(manifest, profile)

    def test_real_currentness_rejects_committed_stale_package_identity(self) -> None:
        selected = self.repository
        manifest = json.loads(selected.results.read_bytes())
        manifest["android_aar"]["source_commit"] = "0" * 40
        digest = selected.fixture._write_results(manifest)
        _git(selected.root, "add", "artifact/results.json")
        _git(selected.root, "commit", "-qm", "record inconsistent package source")
        with self.assertRaisesRegex(
            finalizer.ReleaseReceiptFinalizerError, "Android AAR"
        ):
            finalizer.load_current_results(digest, repository_root=selected.root)

    def test_unknown_then_exact_recovery_uses_live_checkout_without_resending(
        self,
    ) -> None:
        selected = self.repository
        plan = selected.prepare()
        journal = selected.state_root / publication.JOURNAL_DIRECTORY
        remote = MaintenanceRemote(plan, journal)
        remote.fail_after_effect = True

        def publish() -> publication.PublicationStatus:
            return publication.publish_plan(
                profile=PROFILE,
                repository_root=selected.root,
                state_root=selected.state_root,
                execute_real_github_mutation=True,
                expected_plan_sha256=plan.sha256(),
                expected_results_sha256=selected.digest,
                draft_barrier_ack="I_ACKNOWLEDGE_PLATFORM_REVISION_DRAFT_BEFORE_UPLOAD",
                publication_order_ack="I_ACKNOWLEDGE_ORIGINAL_RELEASES_REMAIN_UNCHANGED",
                observer=remote.observe,
                mutator=remote.mutate,
            )

        with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
            publish()
        intent = (journal / "000000-intent.json").read_bytes()
        self.assertTrue((journal / "000000-reconciliation.json").is_file())
        self.assertFalse((journal / "000000-outcome.json").exists())
        self.assertEqual(["create-platform-draft"], remote.mutations)
        status = publish()
        self.assertTrue(status.complete)
        self.assertEqual(9, status.applied_actions)
        self.assertEqual(list(EXPECTED_ACTIONS), remote.mutations)
        self.assertEqual(intent, (journal / "000000-intent.json").read_bytes())
        repeated = publication.verify_publication(
            repository_root=selected.root,
            state_root=selected.state_root,
            observer=remote.observe,
        )
        self.assertTrue(repeated.complete)
        self.assertEqual(list(EXPECTED_ACTIONS), remote.mutations)

    def test_swapped_tag_is_rejected_before_remote_observation(self) -> None:
        selected = self.repository
        plan = selected.prepare()
        _git(selected.root, "tag", "-d", PROFILE.release_tag)
        _git(
            selected.root,
            "tag",
            "-a",
            PROFILE.release_tag,
            selected.pending_commit,
            "-m",
            "wrong target",
        )
        observer = mock.Mock(
            side_effect=AssertionError(
                "local tag failure must precede remote observation"
            )
        )
        with self.assertRaises(publication.StableGitHubPublicationError):
            publication.status_plan(
                repository_root=selected.root,
                state_root=selected.state_root,
                observer=observer,
            )
        observer.assert_not_called()
        self.assertEqual(selected.pending_commit, plan.pending_commit)

    def test_r2_external_checkout_keeps_original_account_lock_and_inode(self) -> None:
        selected = self.repository
        selected.prepare()
        account_lock = selected.account_root / publication.LOCK_LEAF
        before = account_lock.stat().st_ino
        for first, second in (
            (selected.account_root, selected.state_root),
            (selected.state_root, selected.account_root),
        ):
            with self.subTest(first=first.name):
                with publication.publication_lock(
                    first, allow_create=False, repository_root=selected.root
                ):
                    with self.assertRaises(publication.StableGitHubPublicationLockHeld):
                        with publication.publication_lock(
                            second, allow_create=False, repository_root=selected.root
                        ):
                            self.fail(
                                "both publication lanes acquired the account authority"
                            )
        self.assertEqual(before, account_lock.stat().st_ino)

    def test_registered_worktree_exclusion_uses_selected_repository(self) -> None:
        selected = self.repository
        self.assertIn(
            selected.root,
            publication._registered_worktrees(repository_root=selected.root),
        )
        forbidden_home = selected.root / "target" / "account-home"
        forbidden_home.mkdir(mode=0o700)
        with mock.patch.object(
            publication, "_account_home", return_value=forbidden_home
        ):
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError, "inside a registered worktree"
            ):
                publication.ensure_state_root_for_prepare(
                    publication.expected_state_root(PROFILE),
                    repository_root=selected.root,
                )
        self.assertFalse((forbidden_home / ".q-periapt").exists())

    def test_external_checkout_keeps_tool_worktrees_out_of_state_authority(
        self,
    ) -> None:
        selected = self.repository
        tool_root = selected.home / "tool-checkout"
        tool_root.mkdir(mode=0o755)
        tool_root.chmod(0o755)
        _git(tool_root, "init", "-q")
        forbidden_home = tool_root / "target" / "account-home"
        forbidden_home.mkdir(mode=0o700, parents=True)
        with (
            mock.patch.object(publication, "REPOSITORY_ROOT", tool_root),
            mock.patch.object(
                publication, "_account_home", return_value=forbidden_home
            ),
        ):
            roots = publication._registered_worktrees(repository_root=selected.root)
            self.assertEqual({selected.root, tool_root}, set(roots))
            with self.assertRaisesRegex(
                publication.StableGitHubPublicationError, "inside a registered worktree"
            ):
                publication.ensure_state_root_for_prepare(
                    publication.expected_state_root(PROFILE),
                    repository_root=selected.root,
                )
        self.assertFalse((forbidden_home / ".q-periapt").exists())


class CanonicalPublicationRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = pathlib.Path(temporary.name).resolve()
        self.root = self.base / "repository"
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        _git(self.root, "init", "-q")

    def test_owned_0755_clone_is_accepted_without_changing_its_mode(self) -> None:
        self.assertEqual(self.root, git_provenance.canonical_repository_root(self.root))
        self.assertEqual(0o755, self.root.stat().st_mode & 0o777)

    def test_relative_parent_traversal_and_symlink_aliases_are_rejected(self) -> None:
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for root in (
            pathlib.Path("."),
            self.root / ".." / self.root.name,
            alias,
            self.base / "missing",
        ):
            with self.subTest(root=root):
                with self.assertRaises(git_provenance.GitProvenanceError):
                    git_provenance.canonical_repository_root(root)

    def test_group_and_world_writable_roots_are_rejected(self) -> None:
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                self.root.chmod(mode)
                with self.assertRaises(git_provenance.GitProvenanceError):
                    git_provenance.canonical_repository_root(self.root)
        self.root.chmod(0o755)

    def test_root_owned_by_another_identity_is_rejected(self) -> None:
        with mock.patch.object(
            git_provenance.os, "geteuid", return_value=os.geteuid() + 1
        ):
            with self.assertRaises(git_provenance.GitProvenanceError):
                git_provenance.canonical_repository_root(self.root)

    def test_git_file_and_symlink_cannot_replace_independent_git_directory(
        self,
    ) -> None:
        original = self.root / ".git"
        retained = self.base / "retained.git"
        original.rename(retained)
        _write(original, f"gitdir: {retained}\n".encode(), 0o644)
        with self.assertRaises(git_provenance.GitProvenanceError):
            git_provenance.canonical_repository_root(self.root)
        original.unlink()
        original.symlink_to(retained, target_is_directory=True)
        with self.assertRaises(git_provenance.GitProvenanceError):
            git_provenance.canonical_repository_root(self.root)


class ApplePublicationRepositoryRootTests(unittest.TestCase):
    def test_four_selected_apple_files_are_read_from_explicit_checkout(self) -> None:
        fixture = apple_fixtures.AppleStablePublicationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        _git(fixture.root, "init", "-q")
        decoy = fixture.root.parent / "other-public-distribution"
        decoy.mkdir(mode=0o755)
        decoy.chmod(0o755)
        with (
            mock.patch.object(apple_stable_publication, "APPLE_PUBLIC_ROOT", decoy),
            mock.patch.object(
                apple_stable_publication, "APPLE_PUBLIC_DISTRIBUTION", decoy / "missing"
            ),
            mock.patch.object(
                apple_distribution,
                "project_trusted_results_candidate_distribution",
                return_value=fixture.distribution,
            ) as signature_boundary,
        ):
            snapshots = apple_stable_publication.load_pending_publication_assets(
                fixture.pending, repository_root=fixture.root
            )
        self.assertEqual(
            tuple(fixture.asset_bytes.values()),
            tuple(snapshot.data for snapshot in snapshots),
        )
        signature_boundary.assert_called_once()
        self.assertEqual(
            fixture.asset_bytes[apple_distribution.XCFRAMEWORK_ZIP_NAME],
            signature_boundary.call_args.kwargs["zip_data"],
        )


if __name__ == "__main__":
    unittest.main()
