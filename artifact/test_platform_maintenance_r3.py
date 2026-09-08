"""R3 product provenance and revision isolation using local, synthetic fixtures.

Git commits and journal files are real private test objects. Remote and SDK
boundaries use the existing fixture oracles; no result here is release evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
import unittest
from unittest import mock

import android_agp_consumer as agp
import android_agp_test_fixture as agp_fixture
import android_maintenance_bundle as bundle
import github_release_observation as github
import platform_candidate_attestation as candidate
import platform_distribution as assembly
import platform_distribution_contract as distribution
import platform_maintenance as source
import platform_maintenance_contract as maintenance
import platform_publication_contract as dispatcher
import platform_stable_publication as collector
import release_publication_contract as release
import release_receipt_finalizer as finalizer
import stable_github_publication as publication
import test_android_maintenance_bundle as bundle_fixture
import test_platform_maintenance as fixtures
import test_stable_github_publication as stable_fixture
from publication_receipt_io import PublicationReceiptIOError, canonical_json_bytes


R2 = distribution.PlatformReleaseProfile.MAINTENANCE_R2
R3 = distribution.PlatformReleaseProfile.MAINTENANCE_R3


class R3ContractTests(unittest.TestCase):

    def test_candidate_profile_requires_exact_schema_and_complete_identity(
        self,
    ) -> None:
        for profile in distribution.PlatformReleaseProfile:
            receipt = {"schema_version": profile.candidate_receipt_schema}
            if profile.is_maintenance:
                receipt["identity"] = profile.identity()
            self.assertIs(profile, distribution.release_candidate_profile(receipt))
        for receipt in (
            {"schema_version": True},
            {"schema_version": 9},
            {"schema_version": 1, "identity": R3.identity()},
            {"schema_version": 2},
            {"schema_version": 2, "identity": None},
            {"schema_version": 2, "identity": {"distribution_revision": "r3"}},
            {"schema_version": 2, "identity": {**R3.identity(), "extra": True}},
            {
                "schema_version": 2,
                "identity": {**R3.identity(), "release_tag": R2.release_tag},
            },
        ):
            with self.subTest(receipt=receipt):
                with self.assertRaises(distribution.PlatformDistributionContractError):
                    distribution.release_candidate_profile(receipt)

    def test_frozen_r2_fixture_bytes_keep_their_original_digests(self) -> None:
        # Captured from the unchanged C3 implementation before r3 tooling edits.
        values = {
            "plan": fixtures.maintenance_plan().document(),
            "pending": fixtures.revision_receipt(),
            "verified": fixtures.revision_receipt(verified=True),
        }
        self.assertEqual(
            {
                "plan": "f362c0108c5883524f2b7b14eee0879bf407227473838b13651c68032c525768",
                "pending": "f4ceb2c2bb7cbc3f4a7d8fd6c21b7fda9a1313bc513171959a379ae825d2833d",
                "verified": "873963bf7b882ce9c167debb02ce69fb3b1860adc43db829b2abb3b6311bab07",
            },
            {
                name: hashlib.sha256(canonical_json_bytes(value)).hexdigest()
                for name, value in values.items()
            },
        )

    def test_r3_has_exact_product_identity_and_unchanged_asset_count(self) -> None:
        receipt = fixtures.revision_receipt(release_profile=R3)
        self.assertEqual(2, receipt["schema_version"])
        self.assertEqual(
            {
                "commit": "97907371efdda0b629b738f5261c9db149b03875",
                "tree": "719de4a213f26b00034c62ba9014d5102e5586f4",
            },
            receipt["reviewed_product"],
        )
        self.assertEqual("abi2-platforms-v0.1.5-r3", R3.release_tag)
        self.assertEqual("abi2-platforms-v0.1.5-r3-verified", R3.verification_tag)
        self.assertEqual("platform_v0_1_5_r3", R3.publication_key)
        self.assertEqual(
            "platform-v0.1.5-r3-publication-receipt.json", collector.receipt_name(R3)
        )
        self.assertEqual(4, len(distribution.PLATFORM_CANDIDATE_ASSETS))
        self.assertEqual(6, len(distribution.PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS))
        self.assertEqual(7, len(distribution.PUBLIC_ASSET_NAMES))
        self.assertEqual(6, len(distribution.CODEQL_ANALYSIS_CONTRACT))
        self.assertEqual(2, len(distribution.CONSTANT_TIME_JOB_CONTRACT))

    def test_each_profile_rejects_the_other_wrapper(self) -> None:
        for producer, verifier in ((R2, R3), (R3, R2)):
            with self.subTest(producer=producer.value):
                receipt = fixtures.revision_receipt(release_profile=producer)
                with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                    maintenance.publication(receipt, profile=verifier)

    def test_product_anchor_cannot_be_missing_changed_or_extended(self) -> None:
        valid = fixtures.revision_receipt(release_profile=R3)
        for mutation in (
            lambda r: r.pop("reviewed_product"),
            lambda r: r["reviewed_product"].update(commit="0" * 40),
            lambda r: r["reviewed_product"].update(tree="0" * 40),
            lambda r: r["reviewed_product"].update(allow_drift=True),
            lambda r: r.update(schema_version=1),
            lambda r: r["publication"]["identity"].update(distribution_revision="r2"),
        ):
            changed = copy.deepcopy(valid)
            mutation(changed)
            with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                maintenance.publication(changed, profile=R3)

    def test_pending_promotion_and_complete_idempotence_are_preserved(self) -> None:
        pending = fixtures.revision_receipt(release_profile=R3)
        verified = fixtures.revision_receipt(verified=True, release_profile=R3)
        maintenance.validate_transition(None, pending, profile=R3)
        maintenance.validate_transition(pending, verified, profile=R3)
        maintenance.validate_transition(verified, copy.deepcopy(verified), profile=R3)
        for before, after in ((None, verified), (verified, pending), (verified, None)):
            with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                maintenance.validate_transition(before, after, profile=R3)
        changed = copy.deepcopy(verified)
        changed["publication"]["observation"]["assembly_receipt_sha256"] = "0" * 64
        with self.assertRaises(maintenance.PlatformMaintenanceContractError):
            maintenance.validate_transition(pending, changed, profile=R3)

    def test_r3_cannot_omit_canonical_or_either_agp_closure(self) -> None:
        valid = fixtures.revision_receipt(release_profile=R3)
        for mutation in (
            lambda r: r.update(bundle_schema=2),
            lambda r: r.pop("agp_consumers"),
            lambda r: r["agp_consumers"].pop("agp_minimal_release"),
            lambda r: r["agp_consumers"].pop("agp_full_release"),
            lambda r: r["agp_consumers"]["agp_full_release"]["projection"].update(
                passed_tests=[]
            ),
            lambda r: r["agp_consumers"]["agp_minimal_release"]["projection"].update(
                run_id="a" * 32
            ),
        ):
            changed = copy.deepcopy(valid)
            mutation(
                changed["publication"]["observation"]["release_candidate"][
                    "android_runtime_evidence"
                ]
            )
            with self.assertRaises(maintenance.PlatformMaintenanceContractError):
                maintenance.publication(changed, profile=R3)

    def test_independent_revision_sources_cannot_share_current_provenance(self) -> None:
        receipts = {
            p.publication_key: fixtures.revision_receipt(release_profile=p)
            for p in (R2, R3)
        }
        with self.assertRaisesRegex(
            maintenance.PlatformMaintenanceContractError, "mix"
        ):
            maintenance.selected_profile(receipts)
        with self.assertRaises(dispatcher.PlatformPublicationContractError):
            dispatcher.validate_release_publications({"release_publications": receipts})

    def test_plan_is_explicit_platform_only_and_cross_profile_rejected(self) -> None:
        plan = fixtures.maintenance_plan(release_profile=R3)
        self.assertEqual(plan, publication.parse_plan(plan.document()))
        self.assertEqual(9, plan.action_count)
        self.assertEqual(
            list(fixtures.EXPECTED_ACTIONS),
            [a.action_id for a in publication.action_sequence(plan)],
        )
        self.assertEqual((plan.platform,), plan.mutable_releases)
        self.assertIsNone(plan.apple.create_request)
        self.assertIsNone(plan.apple.publish_request)
        self.assertEqual(
            "Q-Periapt 0.1.5 ABI 2 SDK Distribution r3", plan.platform.title
        )
        for profile in (R2.value, "maintenance-r4", "stable", None):
            changed = plan.document()
            changed["profile"] = profile
            with self.assertRaises(publication.StableGitHubPublicationError):
                publication.parse_plan(changed)

    def test_profile_validation_precedes_credentials_or_tag_observation(self) -> None:
        with mock.patch.object(github, "github_cli_environment") as credential:
            for invalid in (
                distribution.PlatformReleaseProfile.STABLE,
                "maintenance-r3",
                None,
            ):
                with self.assertRaises(github.GitHubReleaseObservationError):
                    github.sample_platform_maintenance_tag_state_once(
                        expected_tag_object="1" * 40,
                        expected_commit="2" * 40,
                        expected_tree="3" * 40,
                        profile=invalid,
                    )
            credential.assert_not_called()
        with self.assertRaises(candidate.CandidateAttestationError):
            candidate._main(["--profile", "maintenance-r4", "release-tag"])
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(0, candidate._main(["--profile", R3.value, "release-tag"]))
        self.assertEqual(R3.release_tag + "\n", output.getvalue())


class R3RetainedCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = fixtures._MaintenanceRepository(self, release_profile=R3)

    def retain_candidate(self, profile):
        selected = self.repository
        receipt = copy.deepcopy(selected.cache_receipt)
        receipt["schema_version"] = profile.candidate_receipt_schema
        if profile.is_maintenance:
            receipt["identity"] = profile.identity()
        else:
            receipt.pop("identity")
            receipt["android_runtime_evidence"][
                "bundle_schema"
            ] = profile.runtime_bundle_schema
            receipt["android_runtime_evidence"].pop("agp_consumers")
        distribution.validate_release_candidate_receipt(receipt, profile=profile)
        transaction = selected.cache_root / f"transaction.zzz-retained-{profile.value}"
        transaction.mkdir(mode=0o700)
        payload_root = transaction / assembly.PLATFORM_RELEASE_DIRECTORY_NAME
        payload_root.mkdir(mode=0o755)
        payload_root.chmod(0o755)
        for name, payload in selected.payloads.items():
            fixtures._write(payload_root / name, payload, 0o644)
        path = transaction / assembly.PLATFORM_RELEASE_CANDIDATE_RECEIPT_NAME
        fixtures._write(path, assembly.canonical_json(receipt), 0o600)
        return path, receipt

    def selected_source(self):
        receipt = self.repository.cache_receipt
        return {
            "canonical_source_tree_sha256": receipt["source"][
                "canonical_source_tree_sha256"
            ],
            "tag_commit": receipt["source"]["git_commit"],
            "tag_tree": receipt["source"]["git_tree"],
            "source_date_epoch": receipt["source"]["source_date_epoch"],
        }

    def projection(self, receipt):
        return {
            key: receipt[key]
            for key in (
                "android_runtime_evidence",
                "assets",
                "checksums_sha256",
                "platform_distribution_sha256",
            )
        }

    def test_retained_r1_r2_r3_auto_identification_selection_and_real_plan_staging(
        self,
    ) -> None:
        selected = self.repository
        receipts = {R3: selected.cache_receipt}
        for profile in (distribution.PlatformReleaseProfile.STABLE, R2):
            _path, receipts[profile] = self.retain_candidate(profile)
        before = {
            path: path.read_bytes()
            for path in selected.cache_root.rglob("*")
            if path.is_file()
        }
        before_results = selected.results.read_bytes()
        for profile, receipt in receipts.items():
            with self.subTest(profile=profile.value):
                # The selector reads every retained receipt with profile=None;
                # its dispatch, contract validation and byte reads are unpatched.
                found = assembly.find_selected_release_candidate_bundle(
                    self.projection(receipt),
                    self.selected_source(),
                    profile=profile,
                    repository_root=selected.root,
                )
                self.assertEqual(receipt, found.receipt)
                self.assertEqual(
                    hashlib.sha256(assembly.canonical_json(receipt)).hexdigest(),
                    found.receipt_sha256,
                )
        plan = selected.prepare()
        publication.verify_local_plan(
            selected.state_root, plan, repository_root=selected.root
        )
        self.assertIs(R3, plan.profile)
        self.assertEqual(selected.pending_commit, plan.pending_commit)
        self.assertEqual(9, plan.action_count)
        self.assertEqual(7, len(plan.platform.assets))
        for asset in plan.platform.assets:
            staged = (
                selected.state_root / publication.STAGING_DIRECTORY / asset.staging_leaf
            )
            self.assertEqual(selected.payloads[asset.name], staged.read_bytes())
        self.assertEqual(before_results, selected.results.read_bytes())
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_missing_mixed_or_unknown_retained_identity_rejects_before_staging(
        self,
    ) -> None:
        selected = self.repository
        retained, valid = self.retain_candidate(R2)
        variants = [
            None,
            {},
            {"distribution_revision": "r3"},
            {**R3.identity(), "release_tag": R2.release_tag},
            {**R3.identity(), "release_url": R2.release_url},
            {**R3.identity(), "product_version": "0.1.6"},
            {**R3.identity(), "distribution_revision": "r4"},
            {**R3.identity(), "unexpected": True},
        ]
        before_results = selected.results.read_bytes()
        for index, identity in enumerate(variants):
            with self.subTest(identity=identity):
                changed = copy.deepcopy(valid)
                if identity is None:
                    changed.pop("identity")
                else:
                    changed["identity"] = identity
                retained.write_bytes(assembly.canonical_json(changed))
                staging = selected.root / "target" / f"candidate-staging-{index}"
                staging.mkdir(mode=0o700)
                fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(
                        assembly.PlatformDistributionError,
                        "retained platform candidate",
                    ):
                        assembly.find_selected_release_candidate_bundle(
                            self.projection(selected.cache_receipt),
                            self.selected_source(),
                            staging_directory_fd=fd,
                            staging_leaves={
                                name: name for name in distribution.PUBLIC_ASSET_NAMES
                            },
                            profile=R3,
                            repository_root=selected.root,
                        )
                finally:
                    os.close(fd)
                self.assertEqual([], list(staging.iterdir()))
        self.assertEqual(before_results, selected.results.read_bytes())


class R3LocalGitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.history = fixtures.PlatformMaintenanceFinalizerTests()
        self.history.setUp()
        self.addCleanup(self.history.doCleanups)
        self.fixture = self.history.fixture
        self.product_commit = self.fixture.source_commit
        self.product_tree = self.fixture._git_text(
            "rev-parse", f"{self.product_commit}^{{tree}}"
        )
        self.enterContext(
            mock.patch.multiple(
                maintenance,
                REVIEWED_R3_PRODUCT_COMMIT=self.product_commit,
                REVIEWED_R3_PRODUCT_TREE=self.product_tree,
            )
        )

    def test_real_results_only_pending_verified_and_read_only_finalization(
        self,
    ) -> None:
        pending, _digest, _path = self.history._install(
            verified=False, release_profile=R3
        )
        verified, digest, receipt = self.history._install(
            verified=True, release_profile=R3
        )
        self.assertEqual(pending, self.fixture._git_text("rev-parse", f"{verified}^"))
        before = self.fixture.results.read_bytes()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            finalizer.run(
                argparse.Namespace(
                    command="verify-maintenance",
                    expected_results_sha256=digest,
                    platform_receipt=receipt,
                    profile=R3.value,
                )
            )
        self.assertIn("PLATFORM_MAINTENANCE_RESULTS_VERIFY_PASS", output.getvalue())
        self.assertEqual(before, self.fixture.results.read_bytes())
        self.assertNotIn(R2.publication_key, json.loads(before)["release_publications"])

    def test_r3_receipt_and_wrong_profile_are_rejected_before_install(self) -> None:
        receipt = self.history._receipt(verified=False, release_profile=R3)
        before = self.fixture.results.read_bytes()
        with self.assertRaises(PublicationReceiptIOError):
            finalizer.assemble_maintenance_results(
                self.fixture._current_sha256(), receipt_path=receipt, profile=R2
            )
        self.assertEqual(before, self.fixture.results.read_bytes())

    def test_product_paths_include_all_bindings_and_reject_real_git_changes(
        self,
    ) -> None:
        source.verify_product_source(
            self.fixture.root, self.fixture.results_commit, profile=R3
        )
        (self.fixture.root / "artifact/revision.txt").write_text("reviewed tooling\n")
        self.fixture._git("add", "artifact/revision.txt")
        self.fixture._git("commit", "-qm", "update revision tooling")
        tooling = self.fixture._commit()
        source.verify_product_source(self.fixture.root, tooling, profile=R3)
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            "crates/core/src/lib.rs",
            "bindings/android/jni/new.c",
            "bindings/android/src/Policy.java",
            "bindings/kotlin/src/Policy.kt",
            "bindings/kotlin/build.gradle.kts",
            "bindings/swift/Sources/header.h",
            "bindings/c/smoke.c",
        ):
            with self.subTest(path=path):
                self.fixture._git("checkout", "-q", "--detach", tooling)
                changed = self.fixture.root / path
                changed.parent.mkdir(parents=True, exist_ok=True)
                changed.write_text("different product input\n")
                self.fixture._git("add", path)
                self.fixture._git("commit", "-qm", "change a frozen product input")
                with self.assertRaisesRegex(
                    maintenance.PlatformMaintenanceContractError, "frozen product"
                ):
                    source.verify_product_source(
                        self.fixture.root, self.fixture._commit(), profile=R3
                    )

    def test_r3_requires_exact_product_tree_and_real_ancestry(self) -> None:
        with mock.patch.object(maintenance, "REVIEWED_R3_PRODUCT_TREE", "0" * 40):
            with self.assertRaisesRegex(
                maintenance.PlatformMaintenanceContractError, "tree differs"
            ):
                source.verify_product_source(
                    self.fixture.root, self.fixture.results_commit, profile=R3
                )
        with mock.patch.object(
            maintenance, "REVIEWED_R3_PRODUCT_COMMIT", source.BASE_COHORT_COMMIT
        ):
            with self.assertRaisesRegex(
                maintenance.PlatformMaintenanceContractError, "frozen product"
            ):
                source.verify_product_source(
                    self.fixture.root, self.fixture.results_commit, profile=R3
                )

    def test_installed_r3_leaf_cannot_be_replaced_by_r2_or_another_source(self) -> None:
        self.history._install(verified=False, release_profile=R3)
        current = json.loads(self.fixture.results.read_bytes())
        with self.assertRaises(release.ReleasePublicationContractError):
            release.maintenance_source_identity(current, profile=R2)
        changed = copy.deepcopy(current)
        changed["provenance"]["snapshot_commit"] = "0" * 40
        with self.assertRaisesRegex(
            release.ReleasePublicationContractError, "provenance"
        ):
            release.maintenance_source_identity(changed, profile=R3)

    def test_candidate_currentness_runs_the_r3_product_guard(self) -> None:
        manifest = json.loads(self.fixture.results.read_bytes())
        with (
            mock.patch.object(candidate, "_results_manifest", return_value=manifest),
            mock.patch.object(candidate, "REPOSITORY_ROOT", self.fixture.root),
        ):
            candidate.validate_tag_source_currentness(self.product_commit, profile=R3)
            with mock.patch.object(maintenance, "REVIEWED_R3_PRODUCT_TREE", "0" * 40):
                with self.assertRaises(candidate.CandidateAttestationError):
                    candidate.validate_tag_source_currentness(
                        self.product_commit, profile=R3
                    )


class R3BundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = bundle_fixture.AndroidMaintenanceBundleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_r3_export_revalidates_both_agp_consumers_without_original_inputs(
        self,
    ) -> None:
        f = self.fixture
        f.manifest["profile"] = R3.value
        archive = f._archive("r3-download")
        f._hide_private_inputs()
        with mock.patch.object(
            agp, "run_sdk_tool", side_effect=agp_fixture.sdk_runner
        ) as sdk:
            verified = f._verify(archive, "verified-r3", release_profile=R3)
        self.assertEqual(f.canonical, verified.runtime_bundle.read_bytes())
        self.assertEqual(f.manifest["agp_consumers"], verified.consumers)
        self.assertEqual(
            2, [call.args[0].name for call in sdk.call_args_list].count("apksigner")
        )

    def test_cross_revision_bundle_is_rejected_before_sdk_execution(self) -> None:
        archive = self.fixture._archive("retained-r2")
        with mock.patch.object(agp, "run_sdk_tool") as sdk:
            with self.assertRaisesRegex(
                bundle.AndroidMaintenanceBundleError, "discriminant"
            ):
                self.fixture._verify(archive, "wrong-r3", release_profile=R3)
            sdk.assert_not_called()


class R3TransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        stable_fixture.StableGitHubPublicationTests.setUp(self)
        self.addCleanup(self.temporary.cleanup)
        self.plan = fixtures.maintenance_plan(release_profile=R3)
        self.account_root = self.root
        self.root = self.account_root.with_name("github-platform-v0.1.5-r3")
        self.account_root.rename(self.root)
        self.account_root.mkdir(mode=0o700)
        lock = self.account_root / publication.LOCK_LEAF
        lock.write_bytes(b"")
        lock.chmod(0o600)
        self.r2_root = self.root.with_name("github-platform-v0.1.5-r2")
        self.r2_root.mkdir(mode=0o700)
        for name, data in (
            (publication.LOCK_LEAF, b""),
            ("retained-claim", b"consumed r2 claim\n"),
        ):
            path = self.r2_root / name
            path.write_bytes(data)
            path.chmod(0o600)

    @contextlib.contextmanager
    def _patches(self):
        roots = {
            distribution.PlatformReleaseProfile.STABLE: self.account_root,
            R2: self.r2_root,
            R3: self.root,
        }
        with (
            mock.patch.object(
                publication,
                "expected_state_root",
                side_effect=lambda profile=distribution.PlatformReleaseProfile.STABLE: roots[
                    profile
                ],
            ),
            mock.patch.object(publication, "_registered_worktrees", return_value=()),
            mock.patch.object(
                publication, "_load_prepared_plan", return_value=self.plan
            ),
            mock.patch.object(publication, "verify_local_plan", return_value=None),
        ):
            yield

    def _publish(self, remote):
        return publication.publish_plan(
            profile=R3,
            execute_real_github_mutation=True,
            expected_plan_sha256=self.plan.sha256(),
            expected_results_sha256=self.plan.results_sha256,
            draft_barrier_ack=publication.ACK_MAINTENANCE_DRAFT,
            publication_order_ack=publication.ACK_MAINTENANCE_PUBLICATION,
            state_root=self.root,
            observer=remote.observe,
            mutator=remote.mutate,
        )

    def test_nine_exact_writes_and_idempotence_leave_r2_claim_untouched(self) -> None:
        claim = self.r2_root / "retained-claim"
        before = claim.stat().st_ino, claim.read_bytes()
        remote = fixtures.MaintenanceRemote(
            self.plan, self.root / publication.JOURNAL_DIRECTORY
        )
        with self._patches():
            self.assertTrue(self._publish(remote).complete)
            self.assertTrue(self._publish(remote).complete)
        self.assertEqual(list(fixtures.EXPECTED_ACTIONS), remote.mutations)
        self.assertEqual(before, (claim.stat().st_ino, claim.read_bytes()))

    def test_unknown_effect_is_observed_read_only_then_resumed_without_resend(
        self,
    ) -> None:
        journal = self.root / publication.JOURNAL_DIRECTORY
        remote = fixtures.MaintenanceRemote(self.plan, journal)
        remote.fail_after_effect = True
        with self._patches():
            with self.assertRaises(publication.StableGitHubPublicationOutcomeUnknown):
                self._publish(remote)
            intent = (journal / "000000-intent.json").read_bytes()
            self.assertEqual(["create-platform-draft"], remote.mutations)
            observed = publication.status_plan(
                state_root=self.root, observer=remote.observe
            )
            self.assertEqual(["create-platform-draft"], remote.mutations)
            self.assertTrue(observed.unresolved_intent)
            self.assertFalse((journal / "000000-outcome.json").exists())
            self.assertTrue(self._publish(remote).complete)
        self.assertEqual(intent, (journal / "000000-intent.json").read_bytes())
        self.assertEqual(list(fixtures.EXPECTED_ACTIONS), remote.mutations)

    def test_original_r2_r3_publication_lanes_share_the_same_account_lock(self) -> None:
        with self._patches():
            for held, blocked in (
                (self.r2_root, self.root),
                (self.root, self.r2_root),
                (self.account_root, self.root),
            ):
                with publication.publication_lock(held, allow_create=False):
                    with self.assertRaises(publication.StableGitHubPublicationLockHeld):
                        with publication.publication_lock(blocked, allow_create=False):
                            self.fail(
                                "independent revisions acquired concurrent account authority"
                            )


if __name__ == "__main__":
    unittest.main()
