"""Compatibility, revision authority and ambiguous-outcome regression tests."""

from __future__ import annotations

import copy
import argparse
import contextlib
import dataclasses
import hashlib
import io
import json
import pathlib
import subprocess
import unittest
from unittest import mock

import github_release_observation as github
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


def revision_receipt(*, verified: bool = False) -> dict[str, object]:
    value = verified_receipt() if verified else pending_receipt()
    value["identity"] = PROFILE.identity()
    value["boundary"] = platform.publication_boundary(PROFILE)
    candidate = value["observation"]["candidate_attestation"]
    candidate["certificate_san"] = PROFILE.workflow_uri
    candidate["signer_workflow"] = PROFILE.workflow_uri
    candidate["source_ref"] = PROFILE.release_ref
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
        ] = PROFILE.tag_subject_uri
    return maintenance.wrap_publication(value)


def maintenance_plan() -> publication.PublicationPlan:
    original = fixture_plan()
    mutable = original.platform
    common = {
        "tag": "abi2-platforms-v0.1.5-r2",
        "title": publication.MAINTENANCE_PLATFORM_TITLE,
        "body": publication.MAINTENANCE_PLATFORM_BODY,
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
        profile=PROFILE,
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
        for field, value in (
            ("BASE_COHORT_COMMIT", q_commit),
            ("BASE_SOURCE_COMMIT", self.fixture.source_commit),
        ):
            patcher = mock.patch.object(maintenance_source, field, value)
            patcher.start()
            self.addCleanup(patcher.stop)

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

    def _receipt(self, *, verified: bool) -> pathlib.Path:
        value = revision_receipt(verified=verified)
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
            collector.receipt_name(PROFILE),
            maintenance.wrap_publication(inner),
            "maintenance-verified" if verified else "maintenance-pending",
        )

    def _install(self, *, verified: bool) -> tuple[str, str, pathlib.Path]:
        previous_commit = self.fixture._commit()
        previous_sha256 = self.fixture._current_sha256()
        receipt = self._receipt(verified=verified)
        current, committed = finalizer.assemble_maintenance_results(
            previous_sha256, receipt_path=receipt
        )
        self.assertEqual(previous_commit, committed.commit)
        for key in current.keys() - {"release_publications"}:
            self.assertEqual(committed.manifest[key], current[key])
        retained = {
            key: value
            for key, value in current["release_publications"].items()
            if key != maintenance.PUBLICATION_KEY
        }
        self.assertEqual(
            {
                key: value
                for key, value in committed.manifest["release_publications"].items()
                if key != maintenance.PUBLICATION_KEY
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


if __name__ == "__main__":
    unittest.main()
