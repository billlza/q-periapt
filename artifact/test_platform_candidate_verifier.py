from __future__ import annotations

import hashlib
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


class PlatformCandidateVerifierTests(unittest.TestCase):
    COMMIT = "a" * 40
    ASSETS = (
        "q-periapt-android-0.1.0-alpha.2.aar",
        "q-periapt-android-0.1.0-alpha.2-MANIFEST.json",
        "q-periapt-c-abi2-0.1.0-alpha.2-aarch64-unknown-linux-gnu.tar.gz",
        "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz",
        "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip",
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = pathlib.Path(__file__).resolve().parent.parent
        cls.production_script = cls.repository / "artifact/verify-platform-candidate.sh"
        cls.script = cls.production_script.read_text(encoding="utf-8")
        cls.workflow = (
            cls.repository / ".github/workflows/abi2-platform-candidate.yml"
        ).read_text(encoding="utf-8")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name) / "repository"
        artifact = self.root / "artifact"
        artifact.mkdir(parents=True)
        for relative in (
            "artifact/verify-platform-candidate.sh",
            "artifact/python-env.sh",
            "artifact/python_bootstrap.py",
            "artifact/evidence_io.py",
        ):
            source = self.repository / relative
            destination = self.root / relative
            shutil.copy2(source, destination)

        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.gh_log = self.root / "gh-invocations.log"
        self._write_executable(
            self.fake_bin / "git",
            """#!/bin/sh
set -eu
case "$1:$2" in
    cat-file:-t)
        printf 'tag\\n'
        ;;
    rev-parse:--verify)
        printf '%s\\n' "$FAKE_GIT_COMMIT"
        ;;
    status:--porcelain=v1)
        ;;
    *)
        printf 'unexpected fake git invocation: %s\\n' "$*" >&2
        exit 97
        ;;
esac
""",
        )
        self._write_executable(
            self.fake_bin / "gh",
            """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
case "$1:$2" in
    auth:status)
        ;;
    attestation:verify)
        printf '[{}]\\n'
        ;;
    *)
        printf 'unexpected fake gh invocation: %s\\n' "$*" >&2
        exit 98
        ;;
esac
""",
        )

    @staticmethod
    def _write_executable(path: pathlib.Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        os.chmod(path, 0o755)

    def _candidate(self, name: str) -> pathlib.Path:
        candidate = self.root / f"candidate-{name}"
        candidate.mkdir()
        records: list[tuple[str, str]] = []
        for asset in self.ASSETS:
            data = f"fixture bytes for {asset}\n".encode("utf-8")
            (candidate / asset).write_bytes(data)
            records.append((asset, hashlib.sha256(data).hexdigest()))
        (candidate / "CANDIDATE_SHA256SUMS").write_text(
            "".join(
                f"{digest}  {asset}\n"
                for asset, digest in sorted(records)
            ),
            encoding="ascii",
        )
        return candidate

    def _run(self, candidate: pathlib.Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_GH_LOG": str(self.gh_log),
                "FAKE_GIT_COMMIT": self.COMMIT,
                "PATH": f"{self.fake_bin}{os.pathsep}{environment['PATH']}",
                "QPERIAPT_PYTHON": sys.executable,
            }
        )
        return subprocess.run(
            [
                "/bin/sh",
                str(self.root / "artifact/verify-platform-candidate.sh"),
                str(candidate),
                self.COMMIT,
            ],
            cwd=self.root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _gh_invocations(self) -> list[list[str]]:
        if not self.gh_log.exists():
            return []
        return [
            shlex.split(line)
            for line in self.gh_log.read_text(encoding="utf-8").splitlines()
        ]

    def test_attestation_policy_is_exact_and_rejects_self_hosted_runners(self) -> None:
        for token in (
            '--repo "$REPOSITORY"',
            '--signer-workflow "$SIGNER_WORKFLOW"',
            '--signer-digest "$EXPECTED_COMMIT"',
            '--source-ref "$RELEASE_REF"',
            '--source-digest "$EXPECTED_COMMIT"',
            "--deny-self-hosted-runners",
            "--format json",
        ):
            self.assertIn(token, self.script)
        self.assertIn("refs/remotes/origin/main^{commit}", self.script)
        self.assertIn("git status --porcelain=v1 --untracked-files=all", self.script)

    def test_platform_release_revision_converges_on_r2(self) -> None:
        release_tag = "abi2-platforms-v0.1.0-alpha.2-r2"
        self.assertIn(f"RELEASE_TAG={release_tag}", self.script)
        self.assertIn(f"- {release_tag}", self.workflow)
        self.assertIn(f"group: {release_tag}", self.workflow)
        self.assertIn(f"EXPECTED_REF: refs/tags/{release_tag}", self.workflow)
        self.assertNotIn("abi2-platforms-v0.1.0-alpha.2-r1", self.script)
        self.assertNotIn("abi2-platforms-v0.1.0-alpha.2-r1", self.workflow)

    def test_attestation_job_reverifies_both_linux_archives(self) -> None:
        self.assertIn(
            "Independently verify both Linux candidate archives", self.workflow
        )
        self.assertIn(
            "for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu",
            self.workflow,
        )
        self.assertIn(
            "sh artifact/python-run.sh artifact/deterministic_archive.py extract-tar-gz",
            self.workflow,
        )
        self.assertIn(
            "sh artifact/python-run.sh artifact/c_package_manifest.py",
            self.workflow,
        )
        self.assertIn('--expected-commit "$EXPECTED_COMMIT"', self.workflow)
        self.assertIn(
            '--expected-source-date-epoch "$source_epoch"', self.workflow
        )
        self.assertLess(
            self.workflow.index("Independently verify both Linux candidate archives"),
            self.workflow.index("Generate GitHub build provenance attestations"),
        )

    def test_exact_candidate_assets_and_checksum_attestation_are_named(self) -> None:
        for asset in (*self.ASSETS, "CANDIDATE_SHA256SUMS"):
            self.assertGreaterEqual(self.script.count(asset), 2)
        self.assertIn("assets=6", self.script)

    def test_valid_candidate_executes_six_exact_attestation_verifications(self) -> None:
        candidate = self._candidate("valid")
        process = self._run(candidate)
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertIn(
            f"ABI2_PLATFORM_CANDIDATE_ATTESTATION_VERIFY_PASS assets=6 commit={self.COMMIT}",
            process.stdout,
        )

        invocations = self._gh_invocations()
        self.assertEqual([["auth", "status"]], invocations[:1])
        attestation_invocations = invocations[1:]
        self.assertEqual(6, len(attestation_invocations))
        expected_assets = (*self.ASSETS, "CANDIDATE_SHA256SUMS")
        for invocation, asset in zip(attestation_invocations, expected_assets, strict=True):
            self.assertEqual(
                [
                    "attestation",
                    "verify",
                    str(candidate / asset),
                    "--repo",
                    "billlza/q-periapt",
                    "--signer-workflow",
                    "billlza/q-periapt/.github/workflows/abi2-platform-candidate.yml",
                    "--signer-digest",
                    self.COMMIT,
                    "--source-ref",
                    "refs/tags/abi2-platforms-v0.1.0-alpha.2-r2",
                    "--source-digest",
                    self.COMMIT,
                    "--deny-self-hosted-runners",
                    "--format",
                    "json",
                ],
                invocation,
            )

    def test_invalid_candidate_variants_fail_before_any_gh_invocation(self) -> None:
        def tamper(candidate: pathlib.Path) -> None:
            (candidate / self.ASSETS[0]).write_bytes(b"tampered candidate bytes\n")

        def add_extra(candidate: pathlib.Path) -> None:
            (candidate / "unexpected.bin").write_bytes(b"unexpected\n")

        def add_symlink(candidate: pathlib.Path) -> None:
            (candidate / "unsafe-link").symlink_to(candidate / self.ASSETS[0])

        def remove_asset(candidate: pathlib.Path) -> None:
            (candidate / self.ASSETS[0]).unlink()

        def reorder_sums(candidate: pathlib.Path) -> None:
            path = candidate / "CANDIDATE_SHA256SUMS"
            lines = path.read_text(encoding="ascii").splitlines(keepends=True)
            path.write_text("".join(reversed(lines)), encoding="ascii")

        mutations = (
            ("tampered-checksum", tamper),
            ("extra-file", add_extra),
            ("symlink", add_symlink),
            ("missing-file", remove_asset),
            ("noncanonical-sums", reorder_sums),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                self.gh_log.unlink(missing_ok=True)
                candidate = self._candidate(name)
                mutate(candidate)
                process = self._run(candidate)
                self.assertNotEqual(0, process.returncode, process.stdout)
                self.assertEqual([], self._gh_invocations())


if __name__ == "__main__":
    unittest.main()
