"""SDK publication uses real local archives/journals and a deterministic registry fixture."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from bounded_process import BoundedResult
import crates_io_publication as transaction
import crates_io_publication_contract as legacy
import rust_sdk_publication as publication
from test_crates_io_publication import FixedClock, RegistryFixture
from test_rust_sdk_uploader import SOURCE, write_candidate


class SdkPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.journal = self.root / "journal"
        overrides = {name: "[dependencies]\n" + "".join(f'{dependency} = "=0.2.0"\n' for dependency in dependencies)
                     for name, dependencies in publication.TOPOLOGY if dependencies}
        self.report = write_candidate(self.root, overrides)
        self.report.update(completed_at="2026-08-14T00:00:00Z", source_inputs={"fixture": "explicit synthetic package source"})
        self.report_path = self.root / "RUST_SDK_PACKAGE.json"
        self.report_path.write_text(json.dumps(self.report))
        self.digest = hashlib.sha256(self.report_path.read_bytes()).hexdigest()
        self.source = {"commit": SOURCE, "tree": "b" * 40, "source_inputs_sha256": "c" * 64}
        patch = mock.patch.object(publication, "validate_current_source", return_value=self.source)
        self.source_check = patch.start()
        self.addCleanup(patch.stop)
        self.evidence = publication.load_evidence(self.report_path, self.digest, SOURCE)
        self.registry = RegistryFixture(self.evidence.crates)
        self.clock = FixedClock()
        self.held = False
        self.uploaded_under_lock = []

    @contextlib.contextmanager
    def lock(self):
        self.assertFalse(self.held)
        self.held = True
        try:
            yield
        finally:
            self.held = False

    def upload(self, package, *, credential):
        self.assertTrue(self.held)
        intents = transaction.load_unresolved_upload_intents(self.evidence, journal_root=self.journal)
        self.assertTrue(any(i.crate_name == package.name for i in intents))
        self.uploaded_under_lock.append(package.name)
        return self.registry.upload(package, credential=credential)

    def run_transaction(self, **options):
        args = dict(api_fetcher=self.registry.api, sparse_fetcher=self.registry.sparse, clock=self.clock,
                    sleeper=lambda _: None, receipt_root=self.receipts, journal_root=self.journal,
                    poll_attempts=1, poll_interval_seconds=0)
        args.update(options)
        return transaction.run_prepared_publication_transaction(self.evidence, **args)

    def publish(self, **options):
        args = dict(mode="publish", execute_real_upload=True,
                    irreversible_acknowledgement=publication.RELEASE.acknowledgement,
                    credential_provider=lambda: "cio_fixture_token_123456789", lock_factory=self.lock,
                    upload_runner=self.upload)
        args.update(options)
        return self.run_transaction(**args)

    def test_dry_run_validates_twelve_inputs_without_registry_or_credential_use(self):
        credentials = mock.Mock(side_effect=AssertionError("credential read"))
        result = self.run_transaction(mode="dry-run", credential_provider=credentials)
        self.assertEqual(result.planned_crates, publication.sdk.COHORT)
        self.assertEqual(result.upload_attempts, ())
        self.assertIsNone(result.receipt)
        self.assertEqual(self.registry.fetch_calls, [])
        credentials.assert_not_called()
        self.assertFalse(self.journal.exists())

    def test_twelve_crate_publication_uses_shared_journal_and_dual_observations(self):
        result = self.publish()
        self.assertEqual(tuple(self.registry.upload_calls), publication.sdk.COHORT)
        self.assertEqual(self.uploaded_under_lock, list(publication.sdk.COHORT))
        self.assertEqual(result.receipt["status"], "published_verified")
        self.assertEqual(len(result.written_receipts), 13)
        self.assertEqual(len(list(self.journal.iterdir())), 24)
        publication.validate_receipt(result.receipt)
        with self.assertRaises(legacy.CratesIoPublicationContractError):
            legacy.validate_crates_io_publication_receipt(result.receipt)
        self.assertEqual(transaction.load_unresolved_upload_intents(self.evidence, journal_root=self.journal), ())
        for written in result.written_receipts:
            self.assertEqual(written.path.name, publication.RELEASE.receipt_leaf)
            self.assertEqual(written.sha256, hashlib.sha256(written.path.read_bytes()).hexdigest())
            loaded = transaction.load_previous_receipt(written.path, safe_root=self.receipts,
                         release=publication.RELEASE, validator=publication.validate_receipt)
            self.assertEqual(loaded["observation"]["package_contract"]["report_sha256"], self.digest)

    def test_partial_prefix_resumes_without_reuploading_verified_packages(self):
        self.registry.published.update(publication.sdk.COHORT[:7])
        previous = self.run_transaction(mode="verify").receipt
        result = self.publish(previous_receipt=previous)
        self.assertEqual(tuple(self.registry.upload_calls), publication.sdk.COHORT[7:])
        self.assertEqual(result.receipt["status"], "published_verified")

    def test_unknown_upload_is_durable_blocks_blind_retry_and_reconciles_later(self):
        calls = []
        def unknown(package, *, credential):
            self.assertTrue(self.held)
            calls.append(package.name)
            return BoundedResult(0)
        with self.assertRaises(transaction.CratesIoUploadOutcomeUnknownError) as failed:
            self.publish(upload_runner=unknown)
        previous = failed.exception.verified_receipt
        first = publication.sdk.COHORT[0]
        self.assertEqual(calls, [first])
        self.assertEqual(len(transaction.load_unresolved_upload_intents(self.evidence, journal_root=self.journal)), 1)
        with self.assertRaises(transaction.CratesIoUploadOutcomeUnknownError):
            self.publish(previous_receipt=previous, upload_runner=unknown)
        self.assertEqual(calls, [first])
        self.registry.published.add(first)
        recovered = self.publish(previous_receipt=previous)
        self.assertEqual(tuple(self.registry.upload_calls), publication.sdk.COHORT[1:])
        self.assertEqual(recovered.receipt["status"], "published_verified")

    def test_explicit_unknown_retry_binds_the_old_intent_and_new_absence_receipt(self):
        with self.assertRaises(transaction.CratesIoUploadOutcomeUnknownError) as failed:
            self.publish(upload_runner=lambda *args, **kwargs: BoundedResult(1))
        intent, = transaction.load_unresolved_upload_intents(self.evidence, journal_root=self.journal)
        result = self.publish(previous_receipt=failed.exception.verified_receipt,
                              retry_unknown_intent_sha256=intent.digest)
        self.assertEqual(result.receipt["status"], "published_verified")
        documents = [json.loads(p.read_text()) for p in self.journal.glob("*/" + publication.RELEASE.journal_leaf)]
        retries = [d for d in documents if "retry" in d]
        self.assertEqual(len(retries), 1)
        self.assertEqual(retries[0]["retry"]["intent_sha256"], intent.digest)

    def test_mismatch_or_nonprefix_observation_never_uploads(self):
        first, second = publication.sdk.COHORT[:2]
        self.registry.published.add(second)
        with self.assertRaisesRegex(transaction.CratesIoPublicationError, "prefix"):
            self.publish()
        self.registry.published = {first}
        self.registry.api_overrides[first] = {"checksum": "0" * 64}
        with self.assertRaises(transaction.CratesIoPublicationError):
            self.publish()
        self.assertEqual(self.registry.upload_calls, [])

    def test_receipt_cannot_rebind_source_report_archive_or_dependency_graph(self):
        receipt = self.run_transaction(mode="verify").receipt
        mutations = (
            lambda d: d["observation"]["source"].update(tree="d" * 40),
            lambda d: d["observation"]["package_contract"].update(report_sha256="d" * 64),
            lambda d: d["crates"][0].update(crate_sha256="d" * 64),
            lambda d: d["crates"][7].update(dependencies=[]),
            lambda d: d["identity"].update(product_version="0.1.5"),
        )
        for mutate in mutations:
            altered = copy.deepcopy(receipt)
            mutate(altered)
            with self.assertRaises(transaction.CratesIoPublicationError):
                self.publish(previous_receipt=altered)
        self.assertEqual(self.registry.upload_calls, [])

    def test_report_change_during_lock_acquisition_stops_before_remote_or_upload(self):
        @contextlib.contextmanager
        def changed_lock():
            self.report_path.write_bytes(self.report_path.read_bytes() + b" ")
            yield
        with self.assertRaisesRegex(legacy.CratesIoPublicationContractError, "report changed"):
            self.publish(lock_factory=changed_lock)
        self.assertEqual(self.registry.fetch_calls, [])
        self.assertEqual(self.registry.upload_calls, [])

    def test_archive_changes_and_legacy_acknowledgements_are_refused(self):
        with self.assertRaisesRegex(transaction.CratesIoPublicationError, "acknowledgement"):
            self.publish(irreversible_acknowledgement=transaction.REAL_UPLOAD_ACKNOWLEDGEMENT)
        self.evidence.crates[-1].path.write_bytes(b"changed archive")
        with self.assertRaisesRegex(legacy.CratesIoPublicationContractError, "archive changed"):
            self.run_transaction(mode="dry-run")
        self.assertEqual(self.registry.fetch_calls, [])

    def test_old_reports_without_completion_time_require_regeneration(self):
        del self.report["completed_at"]
        self.report_path.write_text(json.dumps(self.report))
        with self.assertRaisesRegex(legacy.CratesIoPublicationContractError, "completion"):
            publication.load_evidence(self.report_path, hashlib.sha256(self.report_path.read_bytes()).hexdigest(), SOURCE)

    def test_cli_dry_run_and_explicit_publication_boundary(self):
        common = ["--report", str(self.report_path), "--report-sha256", self.digest, "--source-commit", SOURCE]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = publication.main(["dry-run", *common])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "local_inputs_verified")
        for arguments in (["publish", *common], ["verify", *common, "--execute-real-upload"]):
            with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(transaction, "production_lock_factory") as lock:
                self.assertEqual(publication.main(arguments), 1)
            lock.assert_not_called()


class SdkPublicationSourceTests(unittest.TestCase):
    def test_current_source_requires_same_clean_commit_and_all_producer_inputs(self):
        source_inputs = {"fixture": "source inputs"}
        report = {"base_commit": SOURCE, "source_inputs": source_inputs}
        with mock.patch.object(publication.sdk, "inspect_package_source", return_value=(SOURCE, False)) as inspect, \
             mock.patch.object(publication.sdk, "source_identity", return_value=source_inputs), \
             mock.patch.object(publication, "run_git_text", return_value="b" * 40):
            actual = publication.validate_current_source(report, SOURCE)
            self.assertEqual(actual["commit"], SOURCE)
            inspect.assert_called_once_with(publication.sdk.ROOT, allow_dirty=False)
            with self.assertRaisesRegex(legacy.CratesIoPublicationContractError, "commit differs"):
                publication.validate_current_source(report, "c" * 40)
            inspect.return_value = (SOURCE, True)
            with self.assertRaisesRegex(legacy.CratesIoPublicationContractError, "clean"):
                publication.validate_current_source(report, SOURCE)
            inspect.return_value = (SOURCE, False)
            with self.assertRaisesRegex(legacy.CratesIoPublicationContractError, "inputs differ"):
                publication.validate_current_source(dict(report, source_inputs={}), SOURCE)

    def test_sdk_and_legacy_namespace_locks_are_independent_and_cannot_be_cross_selected(self):
        account = transaction.pwd.getpwuid(os.geteuid())
        with tempfile.TemporaryDirectory(prefix=".qperiapt-sdk-release-test.", dir=account.pw_dir) as temporary:
            home = Path(temporary).resolve()
            shared = home / ".q-periapt" / "publication-state"
            shared.parent.mkdir(mode=0o700)
            shared.mkdir(mode=0o700)
            sdk_root = shared / publication.RELEASE.state_leaf
            old_root = shared / transaction.PublicationRelease.ABI2_V0_1_5.state_leaf
            sdk_root.mkdir(mode=0o700)
            old_root.mkdir(mode=0o700)
            with mock.patch.object(transaction.pwd, "getpwuid", return_value=mock.Mock(pw_dir=str(home))):
                sdk_lock = transaction.production_lock_factory(sdk_root, release=publication.RELEASE)
                legacy_lock = transaction.production_lock_factory(old_root)
                with sdk_lock():
                    with legacy_lock():
                        self.assertTrue((sdk_root / publication.RELEASE.lock_leaf).is_file())
                        self.assertTrue((old_root / transaction.CRATES_IO_PUBLICATION_LOCK_NAME).is_file())
                    with self.assertRaises(transaction.CratesIoPublicationLockHeldError):
                        with sdk_lock():
                            self.fail("another SDK publisher acquired the held lock")
                with self.assertRaisesRegex(transaction.CratesIoPublicationError, "fixed account"):
                    transaction.production_lock_factory(sdk_root)
                with self.assertRaisesRegex(transaction.CratesIoPublicationError, "fixed account"):
                    transaction.production_lock_factory(old_root, release=publication.RELEASE)

    def test_closed_publication_topology_matches_actual_cargo_production_edges(self):
        result = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"],
                                cwd=publication.sdk.ROOT, capture_output=True, check=True, timeout=30)
        metadata = json.loads(result.stdout)
        packages = publication.sdk.classify(metadata)
        observed = tuple((name, tuple(other for other in publication.sdk.COHORT if other in {
            d["name"] for d in packages[name]["dependencies"] if d["kind"] != "dev" and d["name"] in publication.sdk.COHORT
        })) for name in publication.sdk.COHORT)
        self.assertEqual(observed, publication.TOPOLOGY)


if __name__ == "__main__":
    unittest.main()
