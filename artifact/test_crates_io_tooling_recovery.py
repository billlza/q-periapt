#!/usr/bin/env python3
"""Real Git lineage tests for the explicit crates.io tooling recovery boundary."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import crates_io_tooling_recovery as recovery
from evidence_io import EvidenceIOError
from release_publication_contract import ReleasePublicationContractError, StableSourceIdentity
from test_release_publication_contract import pending_manifest_fixture


class CratesIoToolingRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self._git("init", "-q")
        self._git("config", "user.name", "Release Tests")
        self._git("config", "user.email", "release-tests@example.invalid")
        for relative, content in {
            "README.md": "release notes\n",
            "Cargo.toml": "[workspace]\n",
            ".github/workflows/ci.yml": "name: CI\n",
            "artifact/results.json": '{"state":"source"}\n',
            "artifact/apple_stable_publication.py": "# Apple verifier\n",
            "artifact/crates_io_publication.py": "# registry coordinator\n",
            "artifact/crates_io_registry_metadata.py": "# metadata derivation\n",
            "artifact/crates_io_uploader_build.py": "# fixed uploader builder\n",
            "artifact/crates_io_uploader_template.py.in": "# uploader template\n",
            "crates/product.txt": "product bytes\n",
        }.items():
            self._write(relative, content)
        self.source_commit = self._commit("source")
        self._write("artifact/results.json", '{"state":"tag"}\n')
        self.tag_commit = self._commit("tag results")
        self.tag_tree = self._git("rev-parse", "HEAD^{tree}")
        self.pending_bytes = b'{"state":"pending"}\n'
        self._write("artifact/results.json", self.pending_bytes.decode("utf-8"))
        self.pending_commit = self._commit("pending results")
        self.pending_digest = hashlib.sha256(self.pending_bytes).hexdigest()
        self._write("artifact/apple_stable_publication.py", "# corrected Apple verifier\n")
        self.base_verifier_commit = self._commit("repair Apple verification")

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["/usr/bin/git", *arguments], cwd=self.root, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        return result.stdout.strip()

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _commit(self, message: str) -> str:
        self._git("add", ".")
        self._git("commit", "-qm", message)
        return self._git("rev-parse", "HEAD")

    def _tooling_commit(self) -> str:
        self._write("artifact/crates_io_publication.py", "# observable registry transaction\n")
        self._write("artifact/crates_io_upload_diagnostic.py", "# bounded diagnostics\n")
        self._write("artifact/crates_io_uploader_template.py.in", "# diagnostic uploader\n")
        self._write("artifact/test_crates_io_uploader_diagnostics.py", "# diagnostics tests\n")
        return self._commit("repair registry diagnostics")

    def _source_identity(self) -> StableSourceIdentity:
        return StableSourceIdentity(
            source_parent_commit=self.source_commit,
            tag_commit=self.tag_commit,
            tag_tree=self.tag_tree,
            canonical_source_tree_sha256="a" * 64,
        )

    def _validate(self, tooling_commit: str, **overrides: str) -> recovery.CratesIoToolingRecoveryLineage:
        arguments = {
            "source_commit": self.source_commit,
            "tag_commit": self.tag_commit,
            "tag_tree": self.tag_tree,
            "canonical_source_tree_sha256": "a" * 64,
            "pending_commit": self.pending_commit,
            "expected_pending_results_sha256": self.pending_digest,
            "base_verifier_commit": self.base_verifier_commit,
            "expected_tooling_commit": tooling_commit,
        }
        arguments.update(overrides)
        with mock.patch.object(recovery, "_pending_source_identity", return_value=self._source_identity()):
            return recovery.validate_crates_io_tooling_recovery_lineage(self.root, **arguments)

    def test_accepts_separate_linear_apple_and_registry_corrections(self) -> None:
        tooling = self._tooling_commit()
        lineage = self._validate(tooling)
        self.assertEqual(self.source_commit, lineage.source_commit)
        self.assertEqual(self.tag_commit, lineage.tag_commit)
        self.assertEqual(self.pending_commit, lineage.pending_commit)
        self.assertEqual(self.base_verifier_commit, lineage.base_verifier_commit)
        self.assertEqual(tooling, lineage.tooling_commit)
        self.assertEqual(self.pending_digest, lineage.pending_results_sha256)
        self.assertIn("artifact/apple_stable_publication.py", lineage.changed_paths)
        self.assertIn("artifact/crates_io_upload_diagnostic.py", lineage.changed_paths)
        self.assertEqual(self.pending_bytes, (self.root / "artifact/results.json").read_bytes())

    def test_accepts_required_recovery_module_tests_and_documentation(self) -> None:
        self._tooling_commit()
        for relative in recovery.CRATES_IO_TOOLING_RECOVERY_ALLOWED_PATHS:
            self._write(relative, "reviewed correction\n")
        tooling = self._commit("document and test registry recovery")
        lineage = self._validate(tooling)
        self.assertTrue(recovery.CRATES_IO_TOOLING_RECOVERY_ALLOWED_PATHS <= set(lineage.changed_paths))

    def test_registry_whitelist_excludes_product_metadata_and_builder(self) -> None:
        forbidden = {
            "Cargo.toml", ".github/workflows/ci.yml", "artifact/results.json",
            "artifact/crates_io_registry_metadata.py", "artifact/crates_io_uploader_build.py",
            "artifact/rust_package_handoff.py", "artifact/rust_publish_contract.py",
            "artifact/apple_stable_publication.py", "artifact/source_results_assembler.py",
            "artifact/release_receipt_finalizer.py",
        }
        self.assertFalse(forbidden & recovery.CRATES_IO_TOOLING_RECOVERY_ALLOWED_PATHS)

    def test_rejects_every_forbidden_registry_change(self) -> None:
        for relative in (
            "crates/product.txt", "Cargo.toml", ".github/workflows/ci.yml",
            "artifact/crates_io_registry_metadata.py", "artifact/crates_io_uploader_build.py",
            "artifact/rust_package_handoff.py", "artifact/rust_publish_contract.py",
            "artifact/source_results_assembler.py", "artifact/release_receipt_finalizer.py",
        ):
            with self.subTest(path=relative):
                self._git("reset", "--hard", self.base_verifier_commit)
                self._tooling_commit()
                self._write(relative, "forbidden change\n")
                tooling = self._commit("change an excluded input")
                with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "V-to-W registry history changed forbidden paths"):
                    self._validate(tooling)

    def test_rejects_apple_changes_after_pinned_verifier_v(self) -> None:
        self._tooling_commit()
        self._write("artifact/apple_stable_publication.py", "# later Apple correction\n")
        tooling = self._commit("change the frozen base verifier")
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "V-to-W registry history changed forbidden paths"):
            self._validate(tooling)

    def test_rejects_registry_change_hidden_in_p_to_v_history(self) -> None:
        self._write("artifact/crates_io_publication.py", "# unreviewed earlier correction\n")
        self.base_verifier_commit = self._commit("extend the Apple recovery range")
        tooling = self._tooling_commit()
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "P-to-V verifier history changed forbidden paths"):
            self._validate(tooling)

    def test_rejects_product_change_even_when_reverted(self) -> None:
        self._write("crates/product.txt", "changed product\n")
        self._commit("change product input")
        self._write("crates/product.txt", "product bytes\n")
        self._commit("restore product input")
        tooling = self._tooling_commit()
        self.assertEqual("", self._git("diff", self.base_verifier_commit, tooling, "--", "crates/product.txt"))
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "changed forbidden paths"):
            self._validate(tooling)

    def test_rejects_product_renamed_into_allowed_module(self) -> None:
        self._git("mv", "crates/product.txt", "artifact/crates_io_tooling_recovery.py")
        tooling = self._commit("rename product into tooling")
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "changed forbidden paths: crates/product.txt"):
            self._validate(tooling)

    def test_rejects_results_change_even_when_reverted(self) -> None:
        self._write("artifact/results.json", '{"state":"changed"}\n')
        self._commit("change results")
        self._write("artifact/results.json", self.pending_bytes.decode("utf-8"))
        self._commit("restore pending results")
        tooling = self._tooling_commit()
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "must not change release results"):
            self._validate(tooling)

    def test_rejects_wrong_pending_digest(self) -> None:
        tooling = self._tooling_commit()
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "explicit digest"):
            self._validate(tooling, expected_pending_results_sha256="b" * 64)

    def test_rejects_source_and_tree_pins_that_differ_from_pending(self) -> None:
        tooling = self._tooling_commit()
        for changes in ({"tag_tree": "b" * 40}, {"canonical_source_tree_sha256": "b" * 64}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "source identity differs"):
                    self._validate(tooling, **changes)

    def test_rejects_pending_identity_tree_that_differs_from_git(self) -> None:
        tooling = self._tooling_commit()
        identity = dataclasses.replace(self._source_identity(), tag_tree="b" * 40)
        with mock.patch.object(self, "_source_identity", return_value=identity):
            with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "tag tree differs from Git"):
                self._validate(tooling, tag_tree="b" * 40)

    def test_rejects_wrong_pending_parent(self) -> None:
        tooling = self._tooling_commit()
        with self.assertRaises(recovery.CratesIoToolingRecoveryError):
            self._validate(tooling, pending_commit=self.tag_commit)

    def test_rejects_dirty_checkout_and_wrong_head(self) -> None:
        tooling = self._tooling_commit()
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "explicit commit W"):
            self._validate(self.base_verifier_commit)
        self._write("README.md", "uncommitted documentation\n")
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "clean checkout"):
            self._validate(tooling)

    def test_rejects_empty_commit(self) -> None:
        self._tooling_commit()
        self._git("commit", "--allow-empty", "-qm", "empty recovery")
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "empty commit"):
            self._validate(self._git("rev-parse", "HEAD"))

    def test_rejects_merge_commit(self) -> None:
        branch = self._git("branch", "--show-current")
        self._git("switch", "-q", "-c", "release-documentation")
        self._write("README.md", "registry recovery notes\n")
        self._commit("document recovery")
        self._git("switch", "-q", branch)
        self._tooling_commit()
        self._git("merge", "--no-ff", "-qm", "merge notes", "release-documentation")
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "linear no-merge chain"):
            self._validate(self._git("rev-parse", "HEAD"))

    def test_rejects_nondistinct_registry_recovery(self) -> None:
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "distinct successor"):
            self._validate(self.base_verifier_commit)

    def test_rejects_malformed_explicit_pins_before_git(self) -> None:
        tooling = self._tooling_commit()
        for changes in (
            {"source_commit": "HEAD"}, {"pending_commit": "--all"},
            {"base_verifier_commit": "HEAD~1"}, {"expected_tooling_commit": tooling.upper()},
            {"expected_pending_results_sha256": "a" * 63},
        ):
            with self.subTest(changes=changes):
                with mock.patch.object(recovery, "inspect_worktree") as inspection:
                    with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "malformed"):
                        self._validate(tooling, **changes)
                    inspection.assert_not_called()

    def test_rechecks_checkout_after_history_validation(self) -> None:
        tooling = self._tooling_commit()
        inspection = recovery.inspect_worktree(self.root)
        changed = dataclasses.replace(inspection, commit=self.base_verifier_commit)
        with mock.patch.object(recovery, "inspect_worktree", side_effect=[inspection, changed]):
            with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "changed during recovery"):
                self._validate(tooling)


class PendingSourceIdentityTests(unittest.TestCase):
    def test_accepts_complete_pending_publication_contract(self) -> None:
        manifest = pending_manifest_fixture()
        identity = recovery._pending_source_identity(json.dumps(manifest).encode("utf-8"))
        self.assertEqual("1" * 40, identity.source_parent_commit)
        self.assertEqual("4" * 40, identity.tag_commit)
        self.assertEqual("5" * 40, identity.tag_tree)

    def test_rejects_corrupted_pending_handoff(self) -> None:
        manifest = pending_manifest_fixture()
        manifest["rust_publish"]["handoff_manifest_sha256"] = "f" * 63
        with self.assertRaises(ReleasePublicationContractError):
            recovery._pending_source_identity(json.dumps(manifest).encode("utf-8"))

    def test_rejects_nonobject_or_duplicate_results(self) -> None:
        with self.assertRaisesRegex(recovery.CratesIoToolingRecoveryError, "JSON object"):
            recovery._pending_source_identity(b"[]")
        with self.assertRaises(EvidenceIOError):
            recovery._pending_source_identity(b'{"state":1,"state":2}')


if __name__ == "__main__":
    unittest.main()
