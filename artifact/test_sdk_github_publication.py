"""Synthetic SDK admissions exercise real Git, private staging and shared journals."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import github_release_observation as github
import sdk_github_publication as sdk
import sdk_github_publication_contract as contract
import stable_github_publication as transaction
from publication_receipt_io import canonical_json_bytes
import test_continuity_release_manifest as manifest_fixtures
import test_github_release_observation as observation_fixtures
from test_stable_github_publication import fixture_snapshot


class SdkGitHubPublicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = manifest_fixtures.ContinuityReleaseManifestTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.release_fixture()
        self.root = f.root
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.account = Path(self.scratch.name).resolve()
        self.input_root = self.account / "input"
        self.payloads = {}
        self.platform_assets = []
        for row in f.document["packages"]:
            previous = row["artifacts"][0]
            name = row["id"] + ".crate"
            raw = (self.root / previous["path"]).read_bytes()
            (self.root / previous["path"]).unlink()
            ref = self.asset("platform", name, raw)
            row["artifacts"] = [ref]
            self.platform_assets.append({"name": name, "file": ref})
            (self.root / row["assessments"][0]["path"]).unlink()
            row["assessments"] = []
            if row["format"] == "distribution":
                (self.root / row["metadata"]["path"]).unlink()
                row["metadata"] = {"path": contract.EVIDENCE_PREFIX + f"distributions/{row['id']}.json",
                                   "bytes": 1, "sha256": "0" * 64}
        f.lock["schema_version"] = 2
        f.save()
        (self.root / "MANIFEST.json").unlink()
        self.git("init", "-q")
        self.git("add", ".")
        self.git("commit", "-qm", "Synthetic source")
        f.source.update(commit=self.git("rev-parse", "HEAD"), tree=self.git("rev-parse", "HEAD^{tree}"))
        for row in f.document["packages"]:
            row["assessments"] = [f.json_file(contract.EVIDENCE_PREFIX + f"qualification/original/{row['id']}.json",
                {"kind": "unit.synthetic", "completed": True, "source_commit": f.source["commit"],
                 "scope": "Synthetic fixture only, not production qualification"})]
            if row["format"] == "distribution":
                row["metadata"] = f.json_file(row["metadata"]["path"], {
                    "schema_version": 1, "kind": "qperiapt.continuity_distribution_identity",
                    "name": row["name"], "version": row["version"], "source": f.source,
                    "dependencies": row["dependencies"], "interfaces": row["interfaces"],
                    "artifacts": row["artifacts"],
                })
        selected = f.json_file(contract.MANIFEST_PATH, f.document)
        qualifications = {}
        for role in contract.REQUIRED_QUALIFICATIONS:
            qualifications[role] = f.json_file(contract.EVIDENCE_PREFIX + f"qualification/{role}.json", {
                "schema_version": 1, "kind": "qperiapt.sdk_release_qualification", "role": role,
                "source": f.source, "completed": True, "scope": "Synthetic control, not release evidence",
                "records": [f.document["packages"][0]["assessments"][0]],
            })
        apple = [{"name": name, "file": self.asset("apple", name, b"synthetic " + name.encode())}
                 for name in contract.APPLE_ASSET_NAMES]
        for name in ("RELEASE_EVIDENCE.zip", "SHA256SUMS"):
            self.platform_assets.append({"name": name, "file": self.asset("platform", name, name.encode())})
        self.admission = {
            "schema_version": 1, "kind": contract.ADMISSION_KIND, "product_version": "0.2.0",
            "boundary": contract.BOUNDARY, "source": f.source, "manifest": selected,
            "qualifications": qualifications,
            "assets": {"apple": apple, "platform": sorted(self.platform_assets, key=lambda a: a["name"])},
        }
        self.admission_ref = f.json_file(contract.ADMISSION_PATH, self.admission)
        self.git("add", contract.EVIDENCE_PREFIX)
        self.git("commit", "-qm", "Synthetic admission")
        for tag in contract.TAGS:
            self.git("tag", "-a", tag, "-m", "Synthetic annotated release")
        shutil.copytree(self.root, self.input_root, ignore=shutil.ignore_patterns(".git"))
        for path, raw in self.payloads.items():
            leaf = self.input_root / path
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.write_bytes(raw)
        self.tool = mock.Mock(sha256=github.SDK_020_GITHUB_CLI_SHA256)

    def git(self, *args):
        completed = subprocess.run(["/usr/bin/git", "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", *args], cwd=self.root,
            check=True, capture_output=True, text=True, timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1"})
        return completed.stdout.strip()

    def asset(self, domain, name, raw):
        path = contract.EVIDENCE_PREFIX + f"assets/{domain}/{name}"
        self.payloads[path] = raw
        return {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    @contextlib.contextmanager
    def local_tools(self):
        with mock.patch.object(github, "select_github_cli", return_value=self.tool) as cli, \
             mock.patch.object(transaction, "_account_home", return_value=self.account), \
             mock.patch.object(transaction, "_registered_worktrees", return_value=(self.root,)):
            yield cli

    def plan(self):
        return sdk.build_plan(self.admission_ref["sha256"], repository_root=self.root)

    def prepare(self):
        return sdk.prepare(self.admission_ref["sha256"], input_root=self.input_root, repository_root=self.root)

    def test_prepare_uses_real_source_evidence_tags_manifest_and_private_staging(self):
        with self.local_tools() as cli, \
             mock.patch.object(github, "github_cli_environment", side_effect=AssertionError("credential access")), \
             mock.patch.object(transaction, "observe_remote_transaction", side_effect=AssertionError("network access")):
            plan = self.prepare()
            state = transaction.expected_state_root(contract.PROFILE)
            transaction.verify_local_plan(state, plan, repository_root=self.root)
            self.assertEqual(plan, transaction.parse_plan(plan.document()))
            self.assertEqual(plan, self.prepare())
            self.assertEqual(plan.source_commit, self.fixture.source["commit"])
            self.assertNotEqual(plan.source_commit, plan.tag_commit)
            self.assertGreater(plan.action_count, transaction.MAX_ACTIONS)
            for call in cli.call_args_list:
                self.assertEqual(call.kwargs, {"profile": "sdk-020"})
            self.assertEqual(list((state / "journal").iterdir()), [])
            for release in plan.releases:
                for asset in release.assets:
                    leaf = state / "staging" / asset.staging_leaf
                    self.assertEqual(hashlib.sha256(leaf.read_bytes()).hexdigest(), asset.sha256)
                    self.assertEqual(leaf.stat().st_mode & 0o777, 0o600)
            legacy = transaction.expected_state_root()
            self.assertEqual({p.name for p in legacy.iterdir()}, {transaction.LOCK_LEAF})

    def test_source_or_checkout_mutation_prevents_preparation(self):
        (self.root / "Cargo.toml").write_text("unreviewed change\n")
        with self.local_tools(), self.assertRaisesRegex(ValueError, "clean"):
            self.prepare()

    def test_evidence_child_may_not_change_product_sources(self):
        (self.root / "Cargo.toml").write_text("unreviewed change\n")
        self.git("add", "Cargo.toml")
        self.git("commit", "--amend", "--no-edit", "-q")
        with self.local_tools(), self.assertRaisesRegex(ValueError, "qualified source"):
            self.plan()

    def test_original_record_bytes_cannot_be_substituted_in_evidence_commit(self):
        ref = self.fixture.document["packages"][0]["assessments"][0]
        (self.root / ref["path"]).write_text('{"completed":true}')
        self.git("add", ref["path"])
        self.git("commit", "--amend", "--no-edit", "-q")
        with self.local_tools(), self.assertRaisesRegex(ValueError, "admission pin"):
            self.plan()

    def test_changed_or_missing_public_asset_is_refused_before_staging(self):
        row = self.admission["assets"]["apple"][1]
        (self.input_root / row["file"]["path"]).write_bytes(b"substitute")
        with self.local_tools(), self.assertRaisesRegex(ValueError, "digest"):
            self.prepare()
        state = self.account / ".q-periapt/publication-state/github-sdk-v0.2.0"
        self.assertFalse((state / transaction.PLAN_LEAF).exists())
        self.assertFalse((state / transaction.PREPARATION_INTENT_LEAF).exists())

    def test_canonical_plan_rejects_legacy_tool_tag_request_and_asset_policy(self):
        with self.local_tools():
            document = self.plan().document()
        changes = (
            lambda d: d.update(github_cli_sha256=github.GITHUB_CLI_SHA256),
            lambda d: d["releases"][0].update(tag="v0.1.5"),
            lambda d: d["releases"][0].update(make_latest=False),
            lambda d: d["releases"][1]["assets"].reverse(),
            lambda d: d["releases"][0]["create_request"].update(sha256="0" * 64),
            lambda d: d["releases"][1]["assets"][0].update(name="../escape.zip"),
            lambda d: d["releases"][1]["assets"][0].update(content_type="application/octet-stream"),
            lambda d: d.update(kind=transaction.PLAN_KIND),
        )
        for change in changes:
            value = copy.deepcopy(document)
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                transaction.parse_plan(value)

    def test_incomplete_or_wrong_source_qualification_is_rejected(self):
        role = "ci"
        record = json.loads((self.input_root / self.admission["qualifications"][role]["path"]).read_bytes())
        for field, value in (("completed", False), ("source", {"commit": "f" * 40, "tree": "e" * 40}),
                             ("records", []), ("failure", "retained failure")):
            bad = copy.deepcopy(record)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.parse_qualification(bad, role=role, source=self.fixture.source)

    def test_missing_qualification_or_package_publication_inventory_is_rejected(self):
        missing = copy.deepcopy(self.admission)
        del missing["qualifications"]["codeql"]
        with self.assertRaises(ValueError):
            contract.parse_admission(missing)
        missing = copy.deepcopy(self.admission)
        missing["assets"]["platform"] = [r for r in missing["assets"]["platform"]
                                            if r["name"] != "engine.crate"]
        with self.assertRaisesRegex(ValueError, "public asset inventory"):
            contract.verify_admission_inputs(self.input_root, missing)

    def test_symlinked_input_refused_without_using_its_target(self):
        ref = self.admission["assets"]["apple"][0]["file"]
        leaf = self.input_root / ref["path"]
        original = self.account / "original.json"
        leaf.rename(original)
        leaf.symlink_to(original)
        with self.local_tools(), self.assertRaises(ValueError):
            self.prepare()

    def test_shared_transaction_journals_variable_inventory_and_is_idempotent(self):
        with self.local_tools():
            plan = self.prepare()
            remote = SdkRemote(plan, transaction.expected_state_root(contract.PROFILE) / "journal")
            with mock.patch.object(sdk, "validate_local_admission", return_value=None):
                status = self.publish(plan, remote)
                again = self.publish(plan, remote)
            self.assertTrue(status.complete and again.complete)
            self.assertEqual(status.applied_actions, plan.action_count)
            self.assertEqual(remote.actions, remote.expected)
            self.assertEqual(len(list(remote.journal.iterdir())), plan.action_count * 3)

    def test_unknown_effect_is_not_retried_and_later_exact_successor_recovers(self):
        with self.local_tools():
            plan = self.prepare()
            remote = SdkRemote(plan, transaction.expected_state_root(contract.PROFILE) / "journal")
            remote.fail_observation_after_effect = True
            with mock.patch.object(sdk, "validate_local_admission", return_value=None):
                with self.assertRaises(transaction.StableGitHubPublicationOutcomeUnknown):
                    self.publish(plan, remote)
                self.assertEqual(remote.actions, ["create-apple-draft"])
                remote.unavailable = False
                status = self.publish(plan, remote)
            self.assertTrue(status.complete)
            self.assertEqual(remote.actions, remote.expected)

    def test_shared_engine_refuses_unjournaled_remote_assets_and_staged_byte_drift(self):
        with self.local_tools():
            plan = self.prepare()
            state = transaction.expected_state_root(contract.PROFILE)
            remote = SdkRemote(plan, state / "journal")
            remote.index = 3
            with self.assertRaisesRegex(ValueError, "journal provenance"):
                self.publish(plan, remote)
            self.assertEqual(remote.actions, [])
            remote.index = 0
            (state / "staging" / plan.apple.assets[0].staging_leaf).write_bytes(b"different bytes")
            with self.assertRaises(ValueError):
                self.publish(plan, remote)
            self.assertEqual(remote.actions, [])

    def test_sdk_cannot_select_legacy_admission_or_namespace(self):
        with self.local_tools():
            plan = self.prepare()
            remote = SdkRemote(plan, transaction.expected_state_root(contract.PROFILE) / "journal")
            with self.assertRaisesRegex(ValueError, "admission selection"):
                self.publish(plan, remote, expected_results_sha256=plan.admission_sha256)
            with self.assertRaisesRegex(ValueError, "state root"):
                self.publish(plan, remote, state_root=transaction.expected_state_root())
            self.assertEqual(remote.actions, [])

    def test_source_drift_after_effect_retains_manual_only_intent(self):
        with self.local_tools():
            plan = self.prepare()
            state = transaction.expected_state_root(contract.PROFILE)
            remote = SdkRemote(plan, state / "journal")
            drift = self.root / "unreviewed-source-change.txt"

            def mutate(*args):
                remote.mutate(*args)
                drift.write_text("Synthetic mutation after the first remote effect\n")

            with self.assertRaises(transaction.StableGitHubPublicationBoundaryIntegrityError):
                self.publish(plan, remote, mutator=mutate)
            self.assertEqual(remote.actions, ["create-apple-draft"])
            self.assertTrue((remote.journal / "000000-intent.json").is_file())
            self.assertFalse((remote.journal / "000000-reconciliation.json").exists())
            drift.unlink()
            with self.assertRaises(transaction.StableGitHubPublicationOutcomeUnknown):
                self.publish(plan, remote)
            self.assertEqual(remote.actions, ["create-apple-draft"])

    def test_shared_observer_selects_sdk_tag_and_cli_profiles_for_both_samples(self):
        with self.local_tools():
            plan = self.plan()
        state = github.StableTagStateObservation(
            repository=transaction.REPOSITORY, state="exact", tag_refs=github.SDK_020_TAG_REFS,
            tag_objects=tuple(r.tag_object for r in plan.releases), commit=plan.tag_commit,
            tree=plan.tag_tree, observation_sha256="d" * 64)
        protection = github.StableTagProtectionObservation(repository=transaction.REPOSITORY,
            ruleset_ids=(1,), tag_refs=github.SDK_020_TAG_REFS, observation_sha256="c" * 64)
        with mock.patch.object(github, "sample_stable_tag_state_once", return_value=state) as tags, \
             mock.patch.object(github, "sample_stable_tag_protection_once", return_value=protection) as rules, \
             mock.patch.object(github, "sample_mutable_release_transaction_once",
                               return_value=fixture_snapshot(plan, 0).releases) as releases:
            observed = transaction.observe_remote_transaction(plan)
        self.assertEqual(transaction.classify_remote_state(plan, observed).index, 0)
        self.assertEqual((tags.call_count, rules.call_count, releases.call_count), (4, 4, 2))
        for call in tags.call_args_list + rules.call_args_list:
            self.assertEqual(call.kwargs["release_profile"], "sdk-020")
        for call in releases.call_args_list:
            self.assertEqual(call.kwargs["cli_profile"], "sdk-020")

    def test_shared_mutation_transport_receives_only_exact_staged_request_fd(self):
        with self.local_tools() as cli:
            plan = self.prepare()
            root = transaction.expected_state_root(contract.PROFILE)
            action = transaction.action_sequence(plan)[0]
            captured = []

            def transport(tool, **options):
                import os
                self.assertIs(tool, self.tool)
                self.assertEqual(options["method"], "POST")
                self.assertEqual(options["endpoint"], "/repos/billlza/q-periapt/releases")
                payload = os.read(options["input_fd"], options["input_size"])
                self.assertEqual(len(payload), options["input_size"])
                self.assertEqual(hashlib.sha256(payload).hexdigest(), options["input_sha256"])
                self.assertEqual(json.loads(payload)["tag_name"], "v0.2.0")
                self.assertEqual(json.loads(payload)["target_commitish"], plan.tag_commit)
                captured.append(payload)

            with transaction.publication_lock(root, allow_create=False, repository_root=self.root) as lock, \
                 mock.patch.object(github, "execute_github_api_json_mutation", side_effect=transport):
                handle = transaction.PrivateDirectoryHandle(path=root, descriptor=lock.primary.root_descriptor,
                    parent_descriptor=-1, name=root.name, device=lock.primary.root_device,
                    inode=lock.primary.root_inode, mode=0o700)
                transaction.execute_production_mutation(handle, plan, action, fixture_snapshot(plan, 0),
                                                       source_environment={"GH_TOKEN": "fixture-token"})
            self.assertEqual(len(captured), 1)
            self.assertEqual(cli.call_args.kwargs, {"profile": "sdk-020"})

    def test_public_verification_requires_attestations_fresh_bytes_and_final_reread(self):
        with self.local_tools():
            plan = self.prepare()
            state = transaction.expected_state_root(contract.PROFILE)
            remote = SdkRemote(plan, state / "journal")
            with mock.patch.object(sdk, "validate_local_admission", return_value=None):
                self.publish(plan, remote)
            verification_root = self.account / "public-verification"
            verification_root.mkdir(mode=0o700)
            mode = "valid"
            downloaded = []

            def capture(tool, args, **options):
                self.assertIs(tool, self.tool)
                self.assertEqual(args[:2], ["release", "verify"])
                release = next(r for r in plan.releases if r.tag == args[2])
                view = fixture_snapshot(plan, plan.action_count).releases.releases[0 if release.domain == "apple" else 1]
                policy = sdk._release_policy(plan, release, view)
                value = observation_fixtures.GitHubReleaseObservationTests().verification()
                result = value["verificationResult"]
                result["verifiedTimestamps"][0]["timestamp"] = view.published_at
                result["statement"]["predicate"].update(databaseId=str(view.release_id),
                    purl=policy.tag_subject_uri, repository=policy.repository, tag=policy.tag)
                result["statement"]["subject"] = github.expected_subjects(policy)
                if mode == "wrong_attestation":
                    result["statement"]["subject"][1]["digest"]["sha256"] = "0" * 64
                return canonical_json_bytes(value)

            def download(tool, args, **options):
                self.assertIs(tool, self.tool)
                self.assertEqual(args[:2], ["release", "download"])
                release = next(r for r in plan.releases if r.tag == args[2])
                name = args[args.index("--pattern") + 1]
                row = next(r for r in self.admission["assets"][release.domain] if r["name"] == name)
                payload = self.payloads[row["file"]["path"]]
                if mode == "wrong_download":
                    payload = b"x" * len(payload)
                transaction.write_private_bytes_noreplace_at(options["output_directory_fd"],
                    options["output_name"], payload, maximum=options["maximum_bytes"], label="synthetic public download")
                downloaded.append(name)

            observations = 0

            def observe(*args, **options):
                nonlocal observations
                observations += 1
                if mode == "late_drift" and observations % 2 == 0:
                    candidates = list(verification_root.glob("observation.*/apple--APPLE_DISTRIBUTION.json"))
                    newest = max(candidates, key=lambda p: p.parent.stat().st_mtime_ns)
                    newest.write_bytes(b"mutated after its first download read")
                return fixture_snapshot(plan, plan.action_count)

            with mock.patch.object(github, "capture_github_cli", side_effect=capture), \
                 mock.patch.object(github, "write_github_cli_stdout_at", side_effect=download), \
                 mock.patch.object(transaction, "observe_remote_transaction", side_effect=observe), \
                 mock.patch.object(sdk, "validate_local_admission", return_value=None):
                receipt, path = sdk.verify_published_assets(verification_root=verification_root,
                    repository_root=self.root, source_environment={"GH_TOKEN": "fixture-token"})
                self.assertTrue(receipt["completed"])
                self.assertEqual(len(downloaded), sum(len(r.assets) for r in plan.releases))
                self.assertEqual(json.loads((path / "PUBLICATION_VERIFICATION.json").read_bytes()), receipt)
                for mode in ("wrong_attestation", "wrong_download", "late_drift"):
                    observations = 0
                    before = set(verification_root.iterdir())
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        sdk.verify_published_assets(verification_root=verification_root,
                            repository_root=self.root, source_environment={"GH_TOKEN": "fixture-token"})
                    failed, = set(verification_root.iterdir()) - before
                    self.assertFalse((failed / "PUBLICATION_VERIFICATION.json").exists())

    def publish(self, plan, remote, **overrides):
        options = dict(execute_real_github_mutation=True, expected_plan_sha256=plan.sha256(),
            expected_admission_sha256=plan.admission_sha256, draft_barrier_ack=transaction.ACK_DRAFT_BARRIER,
            publication_order_ack=transaction.ACK_PUBLICATION_ORDER,
            state_root=transaction.expected_state_root(contract.PROFILE), profile=contract.PROFILE,
            repository_root=self.root, observer=remote.observe, mutator=remote.mutate)
        options.update(overrides)
        return transaction.publish_plan(**options)


class SdkRemote:
    """A deterministic remote model, never evidence of real GitHub publication."""
    def __init__(self, plan, journal):
        self.plan, self.journal = plan, journal
        self.index = 0
        self.actions = []
        self.unavailable = False
        self.fail_observation_after_effect = False
        self.expected = ["create-apple-draft", "create-platform-draft"]
        for release in plan.releases:
            self.expected.extend(f"upload-{release.domain}-{i:02d}-{a.name}" for i, a in enumerate(release.assets))
        self.expected.extend(["publish-apple", "publish-platform"])

    def observe(self, plan):
        if self.unavailable:
            raise github.GitHubCliExecutionError("synthetic unavailable observation", error_kind="timeout", returncode=None)
        return fixture_snapshot(plan, self.index)

    def mutate(self, plan, action, before):
        if action.action_id != self.expected[self.index] or before != fixture_snapshot(plan, self.index):
            raise AssertionError("remote action differs from the independent fixture sequence")
        intent = self.journal / f"{self.index:06d}-intent.json"
        if not intent.is_file() or (self.journal / f"{self.index:06d}-outcome.json").exists():
            raise AssertionError("mutation lacks its durable intent window")
        if json.loads(intent.read_bytes())["plan_sha256"] != plan.sha256():
            raise AssertionError("intent names another plan")
        self.actions.append(action.action_id)
        self.index += 1
        if self.fail_observation_after_effect:
            self.fail_observation_after_effect = False
            self.unavailable = True


if __name__ == "__main__":
    unittest.main()
