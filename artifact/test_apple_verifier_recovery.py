#!/usr/bin/env python3
"""Regression tests for the narrow Apple verifier recovery lineage."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import apple_verifier_recovery as recovery
from release_publication_contract import StableSourceIdentity
from test_release_publication_contract import pending_manifest_fixture


class AppleVerifierRecoveryLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve() / "repository"
        self.root.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Verifier Tests")
        self._git("config", "user.email", "verifier-tests@example.invalid")

        files = {
            "README.md": "release status\n",
            "Cargo.toml": "[workspace]\n",
            ".github/workflows/ci.yml": "name: CI\n",
            "artifact/apple_stable_publication.py": "# original promoter\n",
            "artifact/apple_verifier_recovery.py": "# original lineage gate\n",
            "artifact/results.json": '{"state":"source"}\n',
            "artifact/stable-release-notes.md": "release notes\n",
            "artifact/swift-xcframework-remote-consumer.sh": "# original gate\n",
            "artifact/test_apple_stable_publication.py": "# original tests\n",
            "crates/product.txt": "product bytes\n",
            "docs/EMBEDDING_READINESS.md": "readiness\n",
        }
        for relative, content in files.items():
            self._write(relative, content)
        self._git("add", ".")
        self._git("commit", "-qm", "source")
        self.source_commit = self._git("rev-parse", "HEAD")

        self._write("artifact/results.json", '{"state":"tag"}\n')
        self._commit_all("tag results")
        self.tag_commit = self._git("rev-parse", "HEAD")
        self.tag_tree = self._git("rev-parse", "HEAD^{tree}")

        self.pending_bytes = b'{"state":"pending"}\n'
        (self.root / "artifact/results.json").write_bytes(self.pending_bytes)
        self._commit_all("pending results")
        self.pending_commit = self._git("rev-parse", "HEAD")
        self.pending_sha256 = hashlib.sha256(self.pending_bytes).hexdigest()
        self.branch = self._git("branch", "--show-current")

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _commit_all(self, message: str) -> str:
        self._git("add", ".")
        self._git("commit", "-qm", message)
        return self._git("rev-parse", "HEAD")

    def _verifier_commit(self, *, documentation: bool = False) -> str:
        self._write(
            "artifact/apple_stable_publication.py",
            "# stream-bounded gate helper\n",
        )
        self._write(
            "artifact/swift-xcframework-remote-consumer.sh",
            "# stream-bounded remote gate\n",
        )
        self._write(
            "artifact/test_apple_stable_publication.py",
            "# verifies child artifact writes are not file-size limited\n",
        )
        if documentation:
            self._write("README.md", "published; verifier recovery pending\n")
            self._write(
                "docs/EMBEDDING_READINESS.md",
                "verifier recovery boundary\n",
            )
        return self._commit_all("repair release verifier")

    def _identity(self) -> StableSourceIdentity:
        return StableSourceIdentity(
            source_parent_commit=self.source_commit,
            tag_commit=self.tag_commit,
            tag_tree=self.tag_tree,
            canonical_source_tree_sha256="a" * 64,
        )

    def _validate(self, verifier_commit: str) -> recovery.AppleVerifierRecoveryLineage:
        with mock.patch.object(
            recovery,
            "_pending_source_identity",
            return_value=self._identity(),
        ):
            return recovery.validate_apple_verifier_recovery_lineage(
                self.root,
                source_commit=self.source_commit,
                tag_commit=self.tag_commit,
                pending_commit=self.pending_commit,
                expected_pending_results_sha256=self.pending_sha256,
                expected_verifier_commit=verifier_commit,
            )

    def test_accepts_exact_linear_verifier_and_documentation_delta(self) -> None:
        verifier_commit = self._verifier_commit(documentation=True)

        lineage = self._validate(verifier_commit)

        self.assertEqual(verifier_commit, lineage.verifier_commit)
        self.assertEqual(self.pending_commit, lineage.pending_commit)
        self.assertEqual(self.pending_sha256, lineage.pending_results_sha256)
        self.assertIn(
            "artifact/swift-xcframework-remote-consumer.sh",
            lineage.changed_paths,
        )
        self.assertIn("README.md", lineage.changed_paths)

    def test_pending_source_identity_runs_full_publication_contract(self) -> None:
        pending = pending_manifest_fixture()
        pending_bytes = (
            json.dumps(pending, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")

        identity = recovery._pending_source_identity(pending_bytes)

        self.assertEqual("1" * 40, identity.source_parent_commit)
        self.assertEqual("4" * 40, identity.tag_commit)
        self.assertEqual("5" * 40, identity.tag_tree)

    def test_rejects_product_workflow_and_dependency_changes(self) -> None:
        self._verifier_commit()
        self._write("crates/product.txt", "changed product bytes\n")
        self._write(".github/workflows/ci.yml", "name: changed CI\n")
        self._write("Cargo.toml", "[workspace]\nmembers=[]\n")
        verifier_commit = self._commit_all("change forbidden release inputs")

        with self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "changed forbidden paths",
        ):
            self._validate(verifier_commit)

    def test_rejects_forbidden_path_renamed_to_an_allowed_path(self) -> None:
        self._git(
            "mv",
            "Cargo.toml",
            "artifact/github_release_observation.py",
        )
        verifier_commit = self._commit_all("rename forbidden release input")

        with self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "changed forbidden paths: Cargo.toml",
        ):
            self._validate(verifier_commit)

    def test_rejects_wrong_explicit_pending_base(self) -> None:
        verifier_commit = self._verifier_commit()

        with mock.patch.object(
            recovery,
            "_pending_source_identity",
            return_value=self._identity(),
        ), self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "not exact S-to-R-to-P results-only history",
        ):
            recovery.validate_apple_verifier_recovery_lineage(
                self.root,
                source_commit=self.source_commit,
                tag_commit=self.tag_commit,
                pending_commit=self.tag_commit,
                expected_pending_results_sha256=self.pending_sha256,
                expected_verifier_commit=verifier_commit,
            )

    def test_rejects_merge_in_verifier_history(self) -> None:
        self._git("switch", "-q", "-c", "documentation")
        self._write("README.md", "side documentation change\n")
        self._commit_all("document recovery")
        self._git("switch", "-q", self.branch)
        self._verifier_commit()
        self._git("merge", "--no-ff", "-qm", "merge recovery docs", "documentation")
        verifier_commit = self._git("rev-parse", "HEAD")

        with self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "linear no-merge chain",
        ):
            self._validate(verifier_commit)

    def test_rejects_dirty_verifier_checkout(self) -> None:
        verifier_commit = self._verifier_commit()
        self._write("README.md", "uncommitted recovery change\n")

        with self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "requires a clean checkout",
        ):
            self._validate(verifier_commit)

    def test_rejects_results_mutation_in_verifier_commit(self) -> None:
        self._write(
            "artifact/apple_stable_publication.py",
            "# stream-bounded gate helper\n",
        )
        self._write(
            "artifact/swift-xcframework-remote-consumer.sh",
            "# stream-bounded remote gate\n",
        )
        self._write(
            "artifact/test_apple_stable_publication.py",
            "# regression test\n",
        )
        self._write("artifact/results.json", '{"state":"changed"}\n')
        verifier_commit = self._commit_all("change verifier and results")

        with self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "byte-identical pending results",
        ):
            self._validate(verifier_commit)

    def test_rejects_transient_forbidden_change_even_when_later_reverted(self) -> None:
        self._write("Cargo.toml", "[workspace]\nmembers=[]\n")
        self._commit_all("temporarily change dependency graph")
        self._write("Cargo.toml", "[workspace]\n")
        verifier_commit = self._verifier_commit()

        with self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "changed forbidden paths: Cargo.toml",
        ):
            self._validate(verifier_commit)

    def test_rejects_checkout_other_than_explicit_verifier_commit(self) -> None:
        verifier_commit = self._verifier_commit()

        with mock.patch.object(
            recovery,
            "_pending_source_identity",
            return_value=self._identity(),
        ), self.assertRaisesRegex(
            recovery.AppleVerifierRecoveryError,
            "differs from the explicit verifier commit",
        ):
            recovery.validate_apple_verifier_recovery_lineage(
                self.root,
                source_commit=self.source_commit,
                tag_commit=self.tag_commit,
                pending_commit=self.pending_commit,
                expected_pending_results_sha256=self.pending_sha256,
                expected_verifier_commit=self.pending_commit,
            )


if __name__ == "__main__":
    unittest.main()
