from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import git_provenance


class GitProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self._init_repo(self.root, "target")
        self.tracked = self.root / "tracked.txt"
        self.tracked.write_text("clean\n", encoding="utf-8")
        self._git(self.root, "add", ".")
        self._git(self.root, "commit", "-qm", "fixture")
        self.commit = git_provenance.git_commit(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _git(root: pathlib.Path, *args: str) -> None:
        subprocess.run(["/usr/bin/git", "-C", str(root), *args], check=True)

    def _init_repo(self, root: pathlib.Path, name: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", f"{name} test")
        self._git(root, "config", "user.email", f"{name}@invalid.local")

    def test_clean_repository_passes(self) -> None:
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertFalse(inspection.dirty, inspection.reasons)
        self.assertEqual(inspection.commit, self.commit)

    def test_caller_git_environment_cannot_redirect_repository(self) -> None:
        with tempfile.TemporaryDirectory() as other_temporary:
            other = pathlib.Path(other_temporary).resolve()
            self._init_repo(other, "other")
            (other / "other.txt").write_text("other\n", encoding="utf-8")
            self._git(other, "add", ".")
            self._git(other, "commit", "-qm", "other")
            self.tracked.write_text("dirty\n", encoding="utf-8")
            hostile = {
                "GIT_DIR": str(other / ".git"),
                "GIT_WORK_TREE": str(other),
                "GIT_INDEX_FILE": str(other / ".git" / "index"),
                "PATH": str(other),
            }
            with mock.patch.dict(os.environ, hostile, clear=False):
                inspection = git_provenance.inspect_worktree(self.root)
        self.assertEqual(inspection.commit, self.commit)
        self.assertTrue(inspection.dirty)

    def test_assume_unchanged_and_skip_worktree_are_rejected(self) -> None:
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                self._git(self.root, "update-index", "--no-assume-unchanged", "tracked.txt")
                self._git(self.root, "update-index", "--no-skip-worktree", "tracked.txt")
                self._git(self.root, "update-index", flag, "tracked.txt")
                inspection = git_provenance.inspect_worktree(self.root)
                self.assertTrue(inspection.dirty)
                self.assertTrue(
                    any("special index flags" in reason for reason in inspection.reasons),
                    inspection.reasons,
                )

    def test_same_size_same_mtime_content_change_is_detected(self) -> None:
        before = self.tracked.stat()
        self.tracked.write_text("evil!\n", encoding="utf-8")
        os.utime(self.tracked, ns=(before.st_atime_ns, before.st_mtime_ns))
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty)
        self.assertTrue(
            any("tracked bytes differ" in reason for reason in inspection.reasons),
            inspection.reasons,
        )

    def test_staged_and_untracked_changes_are_detected(self) -> None:
        self.tracked.write_text("staged\n", encoding="utf-8")
        self._git(self.root, "add", "tracked.txt")
        (self.root / "untracked.txt").write_text("new\n", encoding="utf-8")
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty)
        self.assertIn("index differs from HEAD", inspection.reasons)
        self.assertTrue(any("untracked" in reason for reason in inspection.reasons))

    def test_nested_git_repository_under_target_is_ephemeral_output(self) -> None:
        nested = (
            self.root
            / "target"
            / "abi2-platform-publication-worktrees"
            / "M"
        )
        self._init_repo(nested, "nested-target")
        (nested / "tracked.txt").write_text(
            "nested checkout\n",
            encoding="utf-8",
        )
        self._git(nested, "add", "tracked.txt")
        self._git(nested, "commit", "-qm", "nested fixture")

        raw = git_provenance.run_git_bytes(
            self.root,
            ["ls-files", "--others", "-z"],
        )
        self.assertIn(
            b"target/abi2-platform-publication-worktrees/M/\0",
            raw,
        )
        paths = git_provenance.repository_paths(self.root)
        self.assertFalse(
            any(
                path.startswith("target/abi2-platform-publication-worktrees/")
                for path in paths
            ),
            paths,
        )
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertFalse(inspection.dirty, inspection.reasons)

    def test_nested_git_repository_outside_outputs_is_rejected(self) -> None:
        nested = self.root / "release-checkouts" / "M"
        self._init_repo(nested, "nested-source")
        (nested / "tracked.txt").write_text("nested source\n", encoding="utf-8")
        self._git(nested, "add", "tracked.txt")
        self._git(nested, "commit", "-qm", "nested fixture")

        raw = git_provenance.run_git_bytes(
            self.root,
            ["ls-files", "--others", "-z"],
        )
        self.assertIn(b"release-checkouts/M/\0", raw)
        for operation in (
            git_provenance.repository_paths,
            git_provenance.inspect_worktree,
        ):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(
                    git_provenance.GitProvenanceError,
                    "outside declared ephemeral outputs",
                ):
                    operation(self.root)

    def test_sbom_file_exemption_does_not_admit_nested_repositories(self) -> None:
        for leaf in ("fixture.json", "fixture.cdx.json"):
            with self.subTest(leaf=leaf):
                with tempfile.TemporaryDirectory() as temporary:
                    root = pathlib.Path(temporary).resolve() / "repository"
                    self._init_repo(root, "sbom-directory")
                    (root / "tracked.txt").write_text(
                        "clean\n",
                        encoding="utf-8",
                    )
                    self._git(root, "add", "tracked.txt")
                    self._git(root, "commit", "-qm", "outer fixture")

                    nested = root / "sbom" / leaf
                    self._init_repo(nested, "nested-sbom")
                    (nested / "tracked.txt").write_text(
                        "nested source\n",
                        encoding="utf-8",
                    )
                    self._git(nested, "add", "tracked.txt")
                    self._git(nested, "commit", "-qm", "nested fixture")

                    raw = git_provenance.run_git_bytes(
                        root,
                        ["ls-files", "--others", "-z"],
                    )
                    self.assertIn(f"sbom/{leaf}/\0".encode("ascii"), raw)
                    for operation in (
                        git_provenance.repository_paths,
                        git_provenance.inspect_worktree,
                    ):
                        with self.subTest(operation=operation.__name__):
                            with self.assertRaisesRegex(
                                git_provenance.GitProvenanceError,
                                "outside declared ephemeral outputs",
                            ):
                                operation(root)

    def test_untracked_source_symlink_is_not_a_nested_repository_marker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as external_temporary:
            external = pathlib.Path(external_temporary).resolve()
            self._init_repo(external, "external-source")
            (external / "tracked.txt").write_text(
                "external source\n",
                encoding="utf-8",
            )
            self._git(external, "add", "tracked.txt")
            self._git(external, "commit", "-qm", "external fixture")
            link = self.root / "release-checkout-link"
            link.symlink_to(external, target_is_directory=True)

            raw = git_provenance.run_git_bytes(
                self.root,
                ["ls-files", "--others", "-z"],
            )
            self.assertIn(b"release-checkout-link\0", raw)
            self.assertNotIn(b"release-checkout-link/\0", raw)
            self.assertIn(
                "release-checkout-link",
                git_provenance.repository_paths(self.root),
            )
            inspection = git_provenance.inspect_worktree(self.root)
            self.assertTrue(inspection.dirty, inspection.reasons)
            self.assertTrue(
                any(
                    "untracked source-input paths" in reason
                    for reason in inspection.reasons
                ),
                inspection.reasons,
            )

    def test_dirty_tracked_deletion_is_hashed_as_path_absence(self) -> None:
        self.tracked.unlink()

        paths = git_provenance.repository_paths(self.root)
        inspection = git_provenance.inspect_worktree(self.root)

        self.assertNotIn("tracked.txt", paths)
        self.assertTrue(inspection.dirty, inspection.reasons)
        self.assertTrue(
            any(
                "cannot safely open evidence file" in reason
                and "tracked.txt" in reason
                for reason in inspection.reasons
            ),
            inspection.reasons,
        )

    def test_tracked_symlink_replacement_fails_inventory_closed(self) -> None:
        self.tracked.unlink()
        target = self.root / "replacement.txt"
        target.write_text("replacement\n", encoding="utf-8")
        self.tracked.symlink_to(target.name)

        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError,
            "tracked source-input path requires a non-symlink regular file",
        ):
            git_provenance.repository_paths(self.root)

    def test_generated_evidence_only_successor_commit_is_accepted(self) -> None:
        proof_commit = self.commit
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"proof":"bound"}\n', encoding="utf-8")
        self._git(self.root, "add", "artifact/results.json")
        self._git(self.root, "commit", "-qm", "bind generated evidence")

        current = git_provenance.require_commit_or_evidence_successor(
            self.root, proof_commit
        )
        self.assertEqual(current, git_provenance.git_commit(self.root))

    def test_direct_results_only_successor_is_accepted(self) -> None:
        source_commit = self.commit
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"proof":"source-bound"}\n', encoding="utf-8")
        self._git(self.root, "add", "artifact/results.json")
        self._git(self.root, "commit", "-qm", "install source results")

        results_commit = git_provenance.require_direct_results_only_successor(
            self.root,
            source_commit,
        )

        self.assertEqual(results_commit, git_provenance.git_commit(self.root))

    def test_arbitrary_results_child_and_later_results_descendant_are_accepted(
        self,
    ) -> None:
        source_commit = self.commit
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"state":"source"}\n', encoding="utf-8")
        self._git(self.root, "add", "artifact/results.json")
        self._git(self.root, "commit", "-qm", "install source results")
        results_commit = git_provenance.git_commit(self.root)
        results.write_text('{"state":"pending"}\n', encoding="utf-8")
        self._git(self.root, "add", "artifact/results.json")
        self._git(self.root, "commit", "-qm", "record pending receipt")
        pending_commit = git_provenance.git_commit(self.root)

        git_provenance.require_direct_results_only_child(
            self.root, source_commit, results_commit
        )
        git_provenance.require_results_only_descendant(
            self.root, results_commit, pending_commit
        )

    def test_results_descendant_rejects_source_changes_and_unrelated_history(
        self,
    ) -> None:
        source_commit = self.commit
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text("{}\n", encoding="utf-8")
        self._git(self.root, "add", "artifact/results.json")
        self._git(self.root, "commit", "-qm", "install source results")
        results_commit = git_provenance.git_commit(self.root)
        self.tracked.write_text("changed source\n", encoding="utf-8")
        self._git(self.root, "add", "tracked.txt")
        self._git(self.root, "commit", "-qm", "change source")
        changed_commit = git_provenance.git_commit(self.root)

        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError,
            "publication descendant must change exactly artifact/results.json",
        ):
            git_provenance.require_results_only_descendant(
                self.root, results_commit, changed_commit
            )
        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError, "not a descendant"
        ):
            git_provenance.require_commit_ancestor(
                self.root, changed_commit, source_commit
            )

    def test_results_only_successor_rejects_extra_or_empty_changes(self) -> None:
        for extra_source_change in (False, True):
            with self.subTest(
                extra_source_change=extra_source_change
            ), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                self._init_repo(root, "results successor")
                tracked = root / "tracked.txt"
                tracked.write_text("source\n", encoding="utf-8")
                self._git(root, "add", ".")
                self._git(root, "commit", "-qm", "source")
                source_commit = git_provenance.git_commit(root)
                if extra_source_change:
                    results = root / "artifact" / "results.json"
                    results.parent.mkdir()
                    results.write_text("{}\n", encoding="utf-8")
                    tracked.write_text("changed source\n", encoding="utf-8")
                    self._git(root, "add", ".")
                    self._git(root, "commit", "-qm", "mixed successor")
                else:
                    self._git(root, "commit", "--allow-empty", "-qm", "empty successor")
                with self.assertRaisesRegex(
                    git_provenance.GitProvenanceError,
                    "must change exactly artifact/results.json",
                ):
                    git_provenance.require_direct_results_only_successor(
                        root,
                        source_commit,
                    )

    def test_results_only_successor_must_be_the_direct_child(self) -> None:
        source_commit = self.commit
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text("{}\n", encoding="utf-8")
        self._git(self.root, "add", "artifact/results.json")
        self._git(self.root, "commit", "-qm", "install source results")
        self._git(self.root, "commit", "--allow-empty", "-qm", "extra successor")

        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError,
            "exactly the source commit as its parent",
        ):
            git_provenance.require_direct_results_only_successor(
                self.root,
                source_commit,
            )

    def test_results_only_successor_rejects_malformed_source_commit(self) -> None:
        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError,
            "source commit hash is malformed",
        ):
            git_provenance.require_direct_results_only_successor(
                self.root,
                "not-a-commit",
            )

    def test_source_changing_successor_commit_is_rejected(self) -> None:
        proof_commit = self.commit
        self.tracked.write_text("successor source change\n", encoding="utf-8")
        self._git(self.root, "add", "tracked.txt")
        self._git(self.root, "commit", "-qm", "change source")

        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError,
            "successor commit changes canonical source inputs",
        ):
            git_provenance.require_commit_or_evidence_successor(
                self.root, proof_commit
            )

    def test_git_info_and_local_global_excludes_cannot_hide_inputs(self) -> None:
        hidden = self.root / ".cargo" / "config.toml"
        hidden.parent.mkdir()
        hidden.write_text('[build]\nrustflags=["--cfg", "hidden"]\n', encoding="utf-8")

        (self.root / ".git" / "info" / "exclude").write_text(
            ".cargo/config.toml\n", encoding="utf-8"
        )
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty)
        self.assertIn(".cargo/config.toml", git_provenance.repository_paths(self.root))

        (self.root / ".git" / "info" / "exclude").write_text("", encoding="utf-8")
        external = self.root.parent / f"{self.root.name}-exclude"
        external.write_text(".cargo/config.toml\n", encoding="utf-8")
        try:
            self._git(self.root, "config", "core.excludesFile", str(external))
            inspection = git_provenance.inspect_worktree(self.root)
            self.assertTrue(inspection.dirty)
            self.assertIn(".cargo/config.toml", git_provenance.repository_paths(self.root))
        finally:
            external.unlink(missing_ok=True)

    def test_tracked_gitignore_cannot_hide_execution_inputs(self) -> None:
        gitignore = self.root / ".gitignore"
        gitignore.write_text(".cargo/config.toml\n", encoding="utf-8")
        self._git(self.root, "add", ".gitignore")
        self._git(self.root, "commit", "-qm", "declare ignored execution input")

        hidden = self.root / ".cargo" / "config.toml"
        hidden.parent.mkdir()
        hidden.write_text('[build]\nrustflags=["--cfg", "hidden"]\n', encoding="utf-8")
        ignored = subprocess.run(
            ["/usr/bin/git", "-C", str(self.root), "check-ignore", "-q", str(hidden)],
            check=False,
        )
        self.assertEqual(ignored.returncode, 0, "fixture input is not ignored by Git")

        paths = git_provenance.repository_paths(self.root)
        self.assertIn(".cargo/config.toml", paths)
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)
        self.assertTrue(
            any("untracked source-input paths" in reason for reason in inspection.reasons),
            inspection.reasons,
        )

    def test_all_untracked_gitignore_variants_are_rejected(self) -> None:
        scenarios = {
            "root-visible": (".gitignore", ".cargo/config.toml\n"),
            "root-self-hidden": (
                ".gitignore",
                ".gitignore\n.cargo/config.toml\n",
            ),
            "nested-visible": (".cargo/.gitignore", "config.toml\n"),
            "nested-self-hidden": (
                ".cargo/.gitignore",
                ".gitignore\nconfig.toml\n",
            ),
        }
        for name, (gitignore_relative, contents) in scenarios.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                self._init_repo(root, name)
                (root / "tracked.txt").write_text("clean\n", encoding="utf-8")
                self._git(root, "add", ".")
                self._git(root, "commit", "-qm", "fixture")

                hidden = root / ".cargo" / "config.toml"
                hidden.parent.mkdir()
                hidden.write_text(
                    '[build]\nrustflags=["--cfg", "hidden"]\n',
                    encoding="utf-8",
                )
                gitignore = root / gitignore_relative
                gitignore.parent.mkdir(parents=True, exist_ok=True)
                gitignore.write_text(contents, encoding="utf-8")

                inspection = git_provenance.inspect_worktree(root)
                self.assertTrue(inspection.dirty, inspection.reasons)
                self.assertTrue(
                    any(
                        "untracked .gitignore" in reason
                        for reason in inspection.reasons
                    ),
                    inspection.reasons,
                )
                with self.assertRaisesRegex(
                    git_provenance.GitProvenanceError, "untracked .gitignore"
                ):
                    git_provenance.repository_paths(root)

    def test_ignored_python_bytecode_is_dirty_and_blocks_inventory(self) -> None:
        gitignore = self.root / ".gitignore"
        gitignore.write_text("*.pyc\n", encoding="utf-8")
        self._git(self.root, "add", ".gitignore")
        self._git(self.root, "commit", "-qm", "ignore bytecode")

        bytecode = self.root / "artifact" / "__pycache__" / "evidence_io.cpython-313.pyc"
        bytecode.parent.mkdir(parents=True)
        bytecode.write_bytes(b"hostile ignored bytecode\n")
        ignored = subprocess.run(
            ["/usr/bin/git", "-C", str(self.root), "check-ignore", "-q", str(bytecode)],
            check=False,
        )
        self.assertEqual(ignored.returncode, 0, "fixture bytecode is not ignored by Git")

        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)
        self.assertTrue(
            any("Python bytecode caches" in reason for reason in inspection.reasons),
            inspection.reasons,
        )
        with self.assertRaisesRegex(
            git_provenance.GitProvenanceError, "Python bytecode caches"
        ):
            git_provenance.repository_paths(self.root)

    def test_wasm_pack_pkg_outputs_are_fixed_policy_ephemeral(self) -> None:
        package = self.root / "crates" / "q-periapt-wasm" / "pkg"
        package.mkdir(parents=True)
        generated = {
            ".gitignore": "*\n",
            "package.json": '{"name":"q-periapt-wasm"}\n',
            "q_periapt_wasm.js": "export function generated() {}\n",
        }
        for relative, contents in generated.items():
            (package / relative).write_text(contents, encoding="utf-8")
        (package / "q_periapt_wasm_bg.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")

        prefix = "crates/q-periapt-wasm/pkg/"
        paths = git_provenance.repository_paths(self.root)
        self.assertFalse(
            any(path.startswith(prefix) for path in paths),
            [path for path in paths if path.startswith(prefix)],
        )
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertFalse(inspection.dirty, inspection.reasons)

    def test_hqc_candidate_target_is_fixed_policy_ephemeral(self) -> None:
        generated = (
            self.root
            / "research"
            / "hqc-fips207-candidate"
            / "target"
            / "debug"
            / "libcandidate.rlib"
        )
        generated.parent.mkdir(parents=True)
        generated.write_bytes(b"generated research binary\n")

        relative = generated.relative_to(self.root).as_posix()
        self.assertNotIn(relative, git_provenance.repository_paths(self.root))
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertFalse(inspection.dirty, inspection.reasons)

    def test_untracked_finder_metadata_is_a_fixed_policy_non_input(self) -> None:
        baseline_paths = git_provenance.repository_paths(self.root)
        metadata_paths = (
            self.root / ".DS_Store",
            self.root / "nested" / ".DS_Store",
        )
        for path in metadata_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"Finder metadata\n")

        paths = git_provenance.repository_paths(self.root)
        self.assertEqual(paths, baseline_paths)
        for path in metadata_paths:
            self.assertNotIn(path.relative_to(self.root).as_posix(), paths)
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertFalse(inspection.dirty, inspection.reasons)

    def test_finder_metadata_symlink_remains_an_untracked_input(self) -> None:
        metadata = self.root / ".DS_Store"
        metadata.symlink_to(self.tracked.name)

        self.assertIn(".DS_Store", git_provenance.repository_paths(self.root))
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)
        self.assertTrue(
            any("untracked source-input paths" in reason for reason in inspection.reasons),
            inspection.reasons,
        )

    def test_tracked_finder_metadata_remains_a_source_input(self) -> None:
        metadata = self.root / ".DS_Store"
        metadata.write_bytes(b"committed metadata\n")
        self._git(self.root, "add", "-f", ".DS_Store")
        self._git(self.root, "commit", "-qm", "track metadata fixture")

        self.assertIn(".DS_Store", git_provenance.repository_paths(self.root))
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertFalse(inspection.dirty, inspection.reasons)

        metadata.write_bytes(b"changed metadata\n")
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)
        self.assertTrue(
            any("tracked bytes differ" in reason for reason in inspection.reasons),
            inspection.reasons,
        )

    def test_finder_metadata_policy_does_not_exclude_lookalikes(self) -> None:
        lookalikes = {
            ".DS_Store.json": "source metadata\n",
            "lower/.ds_store": "lowercase source\n",
            "upper/.DS_STORE": "uppercase source\n",
            "appledouble/._.DS_Store": "AppleDouble source\n",
            "nested/.DS_Store/payload.rs": "pub const VALUE: u8 = 7;\n",
        }
        for relative, content in lookalikes.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        paths = git_provenance.repository_paths(self.root)
        for relative in lookalikes:
            self.assertIn(relative, paths)
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)

    def test_untracked_fuzz_lockfile_is_a_source_input(self) -> None:
        lockfile = self.root / "fuzz" / "Cargo.lock"
        lockfile.parent.mkdir()
        lockfile.write_text(
            "# This file is automatically @generated by Cargo.\nversion = 4\n",
            encoding="utf-8",
        )

        relative = lockfile.relative_to(self.root).as_posix()
        self.assertIn(relative, git_provenance.repository_paths(self.root))
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)
        self.assertTrue(
            any("untracked source-input paths" in reason for reason in inspection.reasons),
            inspection.reasons,
        )

    def test_output_policy_does_not_exclude_lookalike_source_paths(self) -> None:
        lookalikes = {
            "src/target/payload.rs": "pub const VALUE: u8 = 7;\n",
            "research/another-candidate/target/payload.rs": "pub const VALUE: u8 = 8;\n",
            "payload.rs.bk": "pub const BACKUP: u8 = 9;\n",
            "coverage.profraw": "not an execution profile\n",
            "paper/stale.aux": "\\input{payload}\n",
        }
        for relative, content in lookalikes.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        paths = git_provenance.repository_paths(self.root)
        for relative in lookalikes:
            self.assertIn(relative, paths)
        inspection = git_provenance.inspect_worktree(self.root)
        self.assertTrue(inspection.dirty, inspection.reasons)


if __name__ == "__main__":
    unittest.main()
