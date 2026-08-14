from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from typing import Any

from platform_distribution_contract import (
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    PRODUCT_VERSION,
    RELEASE_TAG,
)


class PlatformCandidateVerifierTests(unittest.TestCase):
    COMMIT = "a" * 40
    PRODUCT_VERSION = PRODUCT_VERSION
    RELEASE_TAG = RELEASE_TAG
    RUN_ID = 31234567890
    VERIFIED_AT = "2026-08-14T01:10:11Z"
    ASSETS = PLATFORM_CANDIDATE_ASSETS
    SUBJECTS = PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS

    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = pathlib.Path(__file__).resolve().parent.parent
        cls.production_script = cls.repository / "artifact/verify-platform-candidate.sh"
        cls.script = cls.production_script.read_text(encoding="utf-8")
        cls.verifier_module = (
            cls.repository / "artifact/platform_candidate_attestation.py"
        ).read_text(encoding="utf-8")
        cls.workflow = (
            cls.repository / ".github/workflows/abi2-platform-candidate.yml"
        ).read_text(encoding="utf-8")
        cls.historical_notes = (
            cls.repository / "artifact/abi2-platform-release-notes.md"
        ).read_text(encoding="utf-8")
        cls.alpha3_notes = (
            cls.repository / "artifact/alpha3-release-notes.md"
        ).read_text(encoding="utf-8")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve() / "repository"
        artifact = self.root / "artifact"
        artifact.mkdir(parents=True)
        for relative in (
            "artifact/verify-platform-candidate.sh",
            "artifact/python-run.sh",
            "artifact/python-env.sh",
            "artifact/python_bootstrap.py",
            "artifact/evidence_io.py",
            "artifact/publication_receipt_io.py",
            "artifact/platform_candidate_attestation.py",
            "artifact/platform_distribution_contract.py",
        ):
            source = self.repository / relative
            destination = self.root / relative
            shutil.copy2(source, destination)

        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.candidate_input_root = (
            self.root / "target" / "abi2-platform-candidate-inputs"
        )
        self.projection_root = (
            self.root / "target" / "abi2-platform-candidate-projections"
        )
        for path in (self.candidate_input_root, self.projection_root):
            path.mkdir(parents=True, mode=0o700)
            os.chmod(path, 0o700)
        self.git_log = self.root / "git-invocations.log"
        self.gh_log = self.root / "gh-invocations.log"
        self.gh_outputs = self.root / "gh-outputs"
        self.gh_outputs.mkdir()
        self._write_executable(
            self.fake_bin / "git",
            """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_GIT_LOG"
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
        asset=${3##*/}
        /bin/cat "$FAKE_GH_OUTPUTS/$asset.json"
        if [ "${FAKE_GH_MUTATE_ASSET:-}" = "$asset" ]; then
            printf 'changed during gh verification\n' >> "$FAKE_GH_MUTATE_PATH"
        fi
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
        candidate = self.candidate_input_root / f"candidate-{name}"
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

    def _subjects(self, candidate: pathlib.Path) -> list[dict[str, object]]:
        return [
            {
                "digest": {
                    "sha256": hashlib.sha256((candidate / asset).read_bytes()).hexdigest()
                },
                "name": asset,
            }
            for asset in self.SUBJECTS
        ]

    def _verification_envelope(
        self, candidate: pathlib.Path, *, run_attempt: int = 1
    ) -> dict[str, object]:
        repository = "billlza/q-periapt"
        repository_url = f"https://github.com/{repository}"
        workflow_path = ".github/workflows/abi2-platform-candidate.yml"
        source_ref = f"refs/tags/{self.RELEASE_TAG}"
        workflow_uri = f"{repository_url}/{workflow_path}@{source_ref}"
        run_uri = (
            f"{repository_url}/actions/runs/{self.RUN_ID}/attempts/{run_attempt}"
        )
        repository_id = "1279236693"
        owner_id = "149552943"
        certificate = {
            "buildConfigDigest": self.COMMIT,
            "buildConfigURI": workflow_uri,
            "buildSignerDigest": self.COMMIT,
            "buildSignerURI": workflow_uri,
            "buildTrigger": "push",
            "certificateIssuer": "https://token.actions.githubusercontent.com",
            "githubWorkflowName": "ABI2 platform release candidate",
            "githubWorkflowRef": source_ref,
            "githubWorkflowRepository": repository,
            "githubWorkflowSHA": self.COMMIT,
            "githubWorkflowTrigger": "push",
            "issuer": "https://fulcio.sigstore.dev",
            "runInvocationURI": run_uri,
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryDigest": self.COMMIT,
            "sourceRepositoryIdentifier": repository_id,
            "sourceRepositoryOwnerIdentifier": owner_id,
            "sourceRepositoryOwnerURI": "https://github.com/billlza",
            "sourceRepositoryRef": source_ref,
            "sourceRepositoryURI": repository_url,
            "sourceRepositoryVisibilityAtSigning": "public",
            "subjectAlternativeName": workflow_uri,
        }
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {
                        "workflow": {
                            "path": workflow_path,
                            "ref": source_ref,
                            "repository": repository_url,
                        }
                    },
                    "internalParameters": {
                        "github": {
                            "event_name": "push",
                            "repository_id": repository_id,
                            "repository_owner_id": owner_id,
                            "runner_environment": "github-hosted",
                        }
                    },
                    "resolvedDependencies": [
                        {
                            "digest": {"gitCommit": self.COMMIT},
                            "uri": f"git+{repository_url}@{source_ref}",
                        }
                    ],
                },
                "runDetails": {
                    "builder": {"id": workflow_uri},
                    "metadata": {"invocationId": run_uri},
                },
            },
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": self._subjects(candidate),
        }
        return {
            "attestation": {"private_fixture": "RAW_ATTESTATION_SENTINEL"},
            "verificationResult": {
                "mediaType": (
                    "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
                ),
                "signature": {"certificate": certificate},
                "statement": statement,
                "verifiedIdentity": {
                    "issuer": {"issuer": "", "regexp": ".*"},
                    "runnerEnvironment": "github-hosted",
                    "subjectAlternativeName": {
                        "regexp": f"^{repository_url}/{workflow_path}",
                        "subjectAlternativeName": "",
                    },
                },
                "verifiedTimestamps": [
                    {
                        "timestamp": "2026-08-14T09:10:11+08:00",
                        "type": "Tlog",
                        "uri": "https://rekor.sigstore.dev",
                    }
                ],
            },
        }

    def _write_gh_response(self, asset: str, value: object) -> None:
        (self.gh_outputs / f"{asset}.json").write_text(
            json.dumps(value, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _install_valid_gh_outputs(
        self, candidate: pathlib.Path, *, run_attempt: int = 1
    ) -> None:
        envelope = self._verification_envelope(
            candidate, run_attempt=run_attempt
        )
        for asset in self.SUBJECTS:
            self._write_gh_response(asset, [copy.deepcopy(envelope)])

    def _mutate_gh_output(
        self,
        asset: str,
        mutation: Callable[[dict[str, Any]], None],
    ) -> None:
        path = self.gh_outputs / f"{asset}.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value[0])
        self._write_gh_response(asset, value)

    def _attestation_directories(self) -> set[pathlib.Path]:
        raw_root = (
            self.root
            / "target"
            / "abi2-platform-candidate-verification"
            / "raw"
        )
        if not raw_root.exists():
            return set()
        return set(raw_root.glob("transaction.*"))

    def _projection_path(self, candidate: pathlib.Path) -> pathlib.Path:
        return (
            self.projection_root
            / candidate.name
            / "candidate-attestation-projection.json"
        )

    def _run(
        self,
        candidate: pathlib.Path,
        *,
        environment_overrides: dict[str, str] | None = None,
        projection_path: pathlib.Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if projection_path is None:
            projection_path = self._projection_path(candidate)
            projection_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(projection_path.parent, 0o700)
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_GH_LOG": str(self.gh_log),
                "FAKE_GH_OUTPUTS": str(self.gh_outputs),
                "FAKE_GIT_LOG": str(self.git_log),
                "FAKE_GIT_COMMIT": self.COMMIT,
                "PATH": f"{self.fake_bin}{os.pathsep}{environment['PATH']}",
                "QPERIAPT_PYTHON": sys.executable,
            }
        )
        if environment_overrides is not None:
            environment.update(environment_overrides)
        return subprocess.run(
            [
                "/bin/sh",
                str(self.root / "artifact/verify-platform-candidate.sh"),
                str(candidate),
                self.COMMIT,
                str(projection_path),
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

    def _git_invocations(self) -> list[list[str]]:
        if not self.git_log.exists():
            return []
        return [
            shlex.split(line)
            for line in self.git_log.read_text(encoding="utf-8").splitlines()
        ]

    def test_attestation_policy_is_exact_and_rejects_self_hosted_runners(self) -> None:
        self.assertEqual(
            stat.S_IMODE(self.production_script.stat().st_mode),
            0o755,
        )
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
        self.assertIn("mktemp -d", self.script)
        self.assertIn('chmod 0700 "$ATTESTATION_DIR"', self.script)
        self.assertNotIn('chmod 0700 "$PRIVATE_PARENT"', self.script)
        self.assertNotIn('chmod 0700 "$TARGET_ROOT"', self.script)
        self.assertNotIn('rm -rf "$ATTESTATION_DIR"', self.script)
        self.assertNotIn("<<'PY'", self.script)
        self.assertNotIn("PYTHONPATH=", self.script)
        self.assertIn("platform_candidate_attestation.py snapshot", self.script)
        self.assertIn("platform_candidate_attestation.py verify", self.script)
        self.assertIn("platform_candidate_attestation.py preflight", self.script)
        self.assertIn(
            "platform_candidate_attestation.py validate-raw-root",
            self.script,
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py preflight"),
            self.script.index("git cat-file"),
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py validate-raw-root"),
            self.script.index("git cat-file"),
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py snapshot"),
            self.script.index("gh auth status"),
        )
        self.assertLess(
            self.script.index("gh auth status"),
            self.script.index("platform_candidate_attestation.py verify"),
        )

    def test_tag_preflight_binds_main_current_semver_and_abi2(self) -> None:
        self.assertIn(
            "test \"$commit\" = \"$(git rev-parse --verify "
            "'refs/remotes/origin/main^{commit}')\"",
            self.workflow,
        )
        self.assertIn(
            "test \"$(jq -r '.package.semver' "
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json)\" "
            f'= "{self.PRODUCT_VERSION}"',
            self.workflow,
        )
        self.assertIn(
            "test \"$(jq -r '.abi.major' "
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json)\" = \"2\"",
            self.workflow,
        )

    def test_platform_release_revision_selects_alpha3_r1(self) -> None:
        release_tag = self.RELEASE_TAG
        self.assertIn("platform_candidate_attestation.py release-tag", self.script)
        self.assertNotIn(f"RELEASE_TAG={release_tag}", self.script)
        self.assertIn(f"- {release_tag}", self.workflow)
        self.assertIn(f"group: {release_tag}", self.workflow)
        self.assertIn(f"EXPECTED_REF: refs/tags/{release_tag}", self.workflow)
        self.assertNotIn("abi2-platforms-v0.1.0-alpha.2-r2", self.script)
        self.assertNotIn("abi2-platforms-v0.1.0-alpha.2-r2", self.workflow)

    def test_historical_r2_verifier_is_not_presented_as_a_current_command(
        self,
    ) -> None:
        self.assertIn(
            "Historical release-time operator transcript",
            self.historical_notes,
        )
        self.assertIn(
            "It is not\na current-HEAD command",
            self.historical_notes,
        )
        self.assertIn(
            "git show abi2-platforms-v0.1.0-alpha.2-r2:artifact/"
            "verify-platform-candidate.sh",
            self.historical_notes,
        )
        self.assertIn(
            'sh artifact/verify-platform-candidate.sh "$CANDIDATE_DIR" '
            '"$TAG_COMMIT"',
            self.historical_notes,
        )
        self.assertNotIn(
            '"$CANDIDATE_DIR" "$TAG_COMMIT" "$projection"',
            self.historical_notes,
        )
        self.assertIn(
            '"$candidate_dir" "$tag_commit" "$projection"',
            self.alpha3_notes,
        )
        self.assertIn(
            "target/abi2-platform-candidate-inputs",
            self.alpha3_notes,
        )
        self.assertIn(
            "target/abi2-platform-candidate-projections",
            self.alpha3_notes,
        )
        self.assertIn(
            "target/abi2-platform-candidate-verification/raw",
            self.alpha3_notes,
        )
        self.assertNotIn(
            "candidate_dir=/absolute/path/to/alpha3-platform-candidate",
            self.alpha3_notes,
        )
        for fixed_apple_root in (
            "target/qperiapt-apple-release-worktrees",
            "target/qperiapt-apple-release-verification",
        ):
            self.assertIn(fixed_apple_root, self.alpha3_notes)
        self.assertNotIn(
            "completed=/absolute/path/to/apple-release/completed.json",
            self.alpha3_notes,
        )

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
        self.assertEqual(
            (*self.ASSETS, "CANDIDATE_SHA256SUMS"),
            self.SUBJECTS,
        )
        self.assertIn("platform_candidate_attestation.py subject-names", self.script)
        self.assertIn("assets=6", self.verifier_module)

        subject_start = self.workflow.index("          subject-path: |\n")
        subject_end = self.workflow.index("\n      - uses:", subject_start)
        subject_lines = self.workflow[subject_start:subject_end].splitlines()[1:]
        expected_subjects = {
            f"candidate/{asset}"
            for asset in self.SUBJECTS
        }
        actual_subjects = [line.strip() for line in subject_lines]
        self.assertEqual(6, len(actual_subjects))
        self.assertEqual(expected_subjects, set(actual_subjects))

    def test_valid_candidate_executes_six_exact_attestation_verifications(self) -> None:
        candidate = self._candidate("valid")
        self._install_valid_gh_outputs(candidate)
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
        expected_assets = self.SUBJECTS
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
                    f"refs/tags/{self.RELEASE_TAG}",
                    "--source-digest",
                    self.COMMIT,
                    "--deny-self-hosted-runners",
                    "--format",
                    "json",
                ],
                invocation,
            )

        attestation_directories = self._attestation_directories()
        self.assertEqual(1, len(attestation_directories))
        raw_directory = attestation_directories.pop()
        self.assertEqual(0o700, stat.S_IMODE(raw_directory.stat().st_mode))
        expected_files = {
            *(f"{asset}.json" for asset in expected_assets),
            *(f"{asset}.stderr" for asset in expected_assets),
            "candidate-snapshot.json",
        }
        self.assertEqual(expected_files, {path.name for path in raw_directory.iterdir()})
        for path in raw_directory.iterdir():
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

        projection_path = self._projection_path(candidate)
        self.assertEqual(0o700, stat.S_IMODE(projection_path.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(projection_path.stat().st_mode))
        projection_bytes = projection_path.read_bytes()
        projection = json.loads(projection_bytes)
        self.assertEqual(
            {
                "certificate_san",
                "predicate_type",
                "signer_workflow",
                "source_digest",
                "source_ref",
                "subjects",
                "verification_record_sha256",
                "verified",
                "verified_at",
                "workflow_run_attempt",
                "workflow_run_id",
            },
            set(projection),
        )
        workflow_uri = (
            "https://github.com/billlza/q-periapt/.github/workflows/"
            f"abi2-platform-candidate.yml@refs/tags/{self.RELEASE_TAG}"
        )
        self.assertEqual(workflow_uri, projection["certificate_san"])
        self.assertEqual(workflow_uri, projection["signer_workflow"])
        self.assertEqual(self.COMMIT, projection["source_digest"])
        self.assertEqual(f"refs/tags/{self.RELEASE_TAG}", projection["source_ref"])
        self.assertEqual(self._subjects(candidate), projection["subjects"])
        self.assertIs(projection["verified"], True)
        self.assertEqual(self.VERIFIED_AT, projection["verified_at"])
        self.assertEqual(1, projection["workflow_run_attempt"])
        self.assertEqual(self.RUN_ID, projection["workflow_run_id"])
        expected_record: Any = self._verification_envelope(candidate)[
            "verificationResult"
        ]
        expected_record["verifiedTimestamps"][0]["timestamp"] = self.VERIFIED_AT
        expected_record_bytes = json.dumps(
            expected_record,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(expected_record_bytes).hexdigest(),
            projection["verification_record_sha256"],
        )
        projection_hash = hashlib.sha256(projection_bytes).hexdigest()
        self.assertRegex(
            process.stdout,
            rf"projection_sha256={projection_hash} run_id={self.RUN_ID}\n$",
        )
        combined_output = process.stdout + process.stderr + projection_bytes.decode("ascii")
        self.assertNotIn("RAW_ATTESTATION_SENTINEL", combined_output)
        self.assertNotIn(str(raw_directory), combined_output)

    def test_rerun_attempt_two_is_projected_without_weakening_identity(self) -> None:
        candidate = self._candidate("attempt-two")
        self._install_valid_gh_outputs(candidate, run_attempt=2)

        process = self._run(candidate)

        self.assertEqual(0, process.returncode, process.stderr)
        projection = json.loads(self._projection_path(candidate).read_bytes())
        self.assertEqual(2, projection["workflow_run_attempt"])
        self.assertEqual(self.RUN_ID, projection["workflow_run_id"])

    def test_empty_legacy_or_ambiguous_gh_results_fail_closed(self) -> None:
        cases: tuple[tuple[str, object | None], ...] = (
            ("legacy-empty-object", [{}]),
            ("empty-output", b""),
            ("empty-result-list", []),
            ("ambiguous-results", None),
        )
        for name, response in cases:
            with self.subTest(name=name):
                self.gh_log.unlink(missing_ok=True)
                candidate = self._candidate(name)
                self._install_valid_gh_outputs(candidate)
                selected_response = response
                if selected_response is None:
                    envelope = self._verification_envelope(candidate)
                    selected_response = [envelope, copy.deepcopy(envelope)]
                if isinstance(selected_response, bytes):
                    (self.gh_outputs / f"{self.ASSETS[0]}.json").write_bytes(
                        selected_response
                    )
                else:
                    self._write_gh_response(self.ASSETS[0], selected_response)
                process = self._run(candidate)
                self.assertNotEqual(0, process.returncode, process.stdout)
                self.assertNotIn("ATTESTATION_VERIFY_PASS", process.stdout)

    def test_attestation_identity_subject_and_statement_mutations_fail_closed(self) -> None:
        def different_statement(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            statement = result["statement"]
            github = statement["predicate"]["buildDefinition"]["internalParameters"][
                "github"
            ]
            certificate = result["signature"]["certificate"]
            github["repository_id"] = "9999999999"
            certificate["sourceRepositoryIdentifier"] = "9999999999"

        def wrong_subject(envelope: dict[str, Any]) -> None:
            envelope["verificationResult"]["statement"]["subject"][0]["digest"][
                "sha256"
            ] = "b" * 64

        def wrong_source(envelope: dict[str, Any]) -> None:
            envelope["verificationResult"]["signature"]["certificate"][
                "sourceRepositoryDigest"
            ] = "b" * 40

        def mismatched_run_attempt(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            run_uri = (
                "https://github.com/billlza/q-periapt/actions/runs/"
                f"{self.RUN_ID}/attempts/2"
            )
            result["signature"]["certificate"]["runInvocationURI"] = run_uri
            result["statement"]["predicate"]["runDetails"]["metadata"][
                "invocationId"
            ] = run_uri

        def zero_run_attempt(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            run_uri = (
                "https://github.com/billlza/q-periapt/actions/runs/"
                f"{self.RUN_ID}/attempts/0"
            )
            result["signature"]["certificate"]["runInvocationURI"] = run_uri
            result["statement"]["predicate"]["runDetails"]["metadata"][
                "invocationId"
            ] = run_uri

        def oversized_run_attempt(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            run_uri = (
                "https://github.com/billlza/q-periapt/actions/runs/"
                f"{self.RUN_ID}/attempts/{1 << 31}"
            )
            result["signature"]["certificate"]["runInvocationURI"] = run_uri
            result["statement"]["predicate"]["runDetails"]["metadata"][
                "invocationId"
            ] = run_uri

        def unbounded_decimal_run_attempt(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            run_uri = (
                "https://github.com/billlza/q-periapt/actions/runs/"
                f"{self.RUN_ID}/attempts/{'9' * 5000}"
            )
            result["signature"]["certificate"]["runInvocationURI"] = run_uri
            result["statement"]["predicate"]["runDetails"]["metadata"][
                "invocationId"
            ] = run_uri

        def unbounded_decimal_run_id(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            run_uri = (
                "https://github.com/billlza/q-periapt/actions/runs/"
                f"{'9' * 5000}/attempts/2"
            )
            result["signature"]["certificate"]["runInvocationURI"] = run_uri
            result["statement"]["predicate"]["runDetails"]["metadata"][
                "invocationId"
            ] = run_uri

        def wrong_certificate(envelope: dict[str, Any]) -> None:
            envelope["verificationResult"]["signature"]["certificate"][
                "subjectAlternativeName"
            ] = "https://github.com/billlza/q-periapt/.github/workflows/other.yml"

        def self_hosted(envelope: dict[str, Any]) -> None:
            result = envelope["verificationResult"]
            result["signature"]["certificate"]["runnerEnvironment"] = "self-hosted"
            result["statement"]["predicate"]["buildDefinition"]["internalParameters"][
                "github"
            ]["runner_environment"] = "self-hosted"
            result["verifiedIdentity"]["runnerEnvironment"] = "self-hosted"

        def wrong_predicate(envelope: dict[str, Any]) -> None:
            envelope["verificationResult"]["statement"]["predicateType"] = (
                "https://example.invalid/predicate"
            )

        mutations = (
            ("different-statement", "CANDIDATE_SHA256SUMS", different_statement),
            ("wrong-subject", self.ASSETS[0], wrong_subject),
            ("wrong-source", self.ASSETS[0], wrong_source),
            ("mismatched-run-attempt", self.ASSETS[0], mismatched_run_attempt),
            ("zero-run-attempt", self.ASSETS[0], zero_run_attempt),
            ("oversized-run-attempt", self.ASSETS[0], oversized_run_attempt),
            (
                "unbounded-decimal-run-attempt",
                self.ASSETS[0],
                unbounded_decimal_run_attempt,
            ),
            (
                "unbounded-decimal-run-id",
                self.ASSETS[0],
                unbounded_decimal_run_id,
            ),
            ("wrong-certificate", self.ASSETS[0], wrong_certificate),
            ("self-hosted", self.ASSETS[0], self_hosted),
            ("wrong-predicate", self.ASSETS[0], wrong_predicate),
        )
        for name, asset, mutation in mutations:
            with self.subTest(name=name):
                self.gh_log.unlink(missing_ok=True)
                candidate = self._candidate(name)
                self._install_valid_gh_outputs(candidate)
                self._mutate_gh_output(asset, mutation)
                before = self._attestation_directories()
                process = self._run(candidate)
                self.assertNotEqual(0, process.returncode, process.stdout)
                self.assertNotIn("ATTESTATION_VERIFY_PASS", process.stdout)
                created = self._attestation_directories() - before
                self.assertEqual(1, len(created))
                created.pop()
                self.assertFalse(self._projection_path(candidate).exists())

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

    def test_existing_projection_fails_before_any_gh_invocation(self) -> None:
        candidate = self._candidate("existing-projection")
        self._install_valid_gh_outputs(candidate)
        projection = self._projection_path(candidate)
        projection.parent.mkdir(parents=True, mode=0o700)
        os.chmod(projection.parent, 0o700)
        projection.write_bytes(b"preexisting projection\n")
        os.chmod(projection, 0o600)

        process = self._run(candidate, projection_path=projection)

        self.assertNotEqual(0, process.returncode, process.stdout)
        self.assertEqual([], self._gh_invocations())
        self.assertEqual(b"preexisting projection\n", projection.read_bytes())

    def test_non_private_projection_parent_fails_before_gh(self) -> None:
        candidate = self._candidate("broad-projection-parent")
        self._install_valid_gh_outputs(candidate)
        parent = self.projection_root / "broad-projection-parent"
        parent.mkdir(mode=0o755)
        os.chmod(parent, 0o755)
        projection = parent / "candidate-attestation-projection.json"

        process = self._run(candidate, projection_path=projection)

        self.assertNotEqual(0, process.returncode, process.stdout)
        self.assertEqual([], self._gh_invocations())
        self.assertFalse(projection.exists())

    def test_candidate_change_during_gh_verification_fails_closed(self) -> None:
        candidate = self._candidate("post-gh-drift")
        self._install_valid_gh_outputs(candidate)

        process = self._run(
            candidate,
            environment_overrides={
                "FAKE_GH_MUTATE_ASSET": self.SUBJECTS[0],
                "FAKE_GH_MUTATE_PATH": str(candidate / self.ASSETS[0]),
            },
        )

        self.assertNotEqual(0, process.returncode, process.stdout)
        self.assertEqual(7, len(self._gh_invocations()))
        self.assertFalse(self._projection_path(candidate).exists())

    def test_relative_projection_path_is_rejected_before_git_or_gh(self) -> None:
        candidate = self._candidate("relative-projection")
        self._install_valid_gh_outputs(candidate)

        process = self._run(
            candidate,
            projection_path=pathlib.Path("candidate-attestation-projection.json"),
        )

        self.assertEqual(2, process.returncode, process.stdout)
        self.assertEqual([], self._gh_invocations())

    def test_projection_inside_candidate_fails_before_any_gh_invocation(self) -> None:
        candidate = self._candidate("projection-inside-candidate")
        self._install_valid_gh_outputs(candidate)
        projection = candidate / "candidate-attestation-projection.json"

        process = self._run(candidate, projection_path=projection)

        self.assertNotEqual(0, process.returncode, process.stdout)
        self.assertIn("outside its fixed safe root", process.stderr)
        self.assertEqual([], self._gh_invocations())
        self.assertFalse(projection.exists())

    def test_unsafe_fixed_root_paths_fail_before_git_or_gh(self) -> None:
        safe_candidate = self._candidate("path-policy-safe")
        safe_projection = self._projection_path(safe_candidate)
        safe_projection.parent.mkdir(parents=True, mode=0o700)
        os.chmod(safe_projection.parent, 0o700)

        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        evil_prefix = (
            self.root / "target" / "abi2-platform-candidate-inputs-evil"
        )
        evil_prefix.mkdir()
        symlink_candidate = self.candidate_input_root / "candidate-link"
        symlink_candidate.symlink_to(outside, target_is_directory=True)
        projection_link = self.projection_root / "projection-link"
        projection_link.symlink_to(outside, target_is_directory=True)

        cases = (
            (
                "tmp",
                pathlib.Path("/tmp/qperiapt-platform-candidate"),
                safe_projection,
            ),
            ("target-evil", evil_prefix, safe_projection),
            (
                "traversal",
                self.candidate_input_root / "child" / ".." / ".." / "outside",
                safe_projection,
            ),
            ("candidate-symlink", symlink_candidate, safe_projection),
            (
                "projection-symlink",
                safe_candidate,
                projection_link / "candidate-attestation-projection.json",
            ),
        )
        for name, candidate, projection in cases:
            with self.subTest(name=name):
                self.git_log.unlink(missing_ok=True)
                self.gh_log.unlink(missing_ok=True)
                process = self._run(candidate, projection_path=projection)
                self.assertNotEqual(0, process.returncode, process.stdout)
                self.assertEqual([], self._git_invocations())
                self.assertEqual([], self._gh_invocations())
                self.assertFalse(projection.exists())

    def test_non_private_fixed_verification_roots_fail_before_git_or_gh(self) -> None:
        candidate = self._candidate("raw-root-mode")
        verification_root = (
            self.root
            / "target"
            / "abi2-platform-candidate-verification"
        )
        raw_root = verification_root / "raw"
        raw_root.mkdir(parents=True, mode=0o700)
        os.chmod(verification_root, 0o700)
        os.chmod(raw_root, 0o700)

        for unsafe_root in (verification_root, raw_root):
            with self.subTest(root=unsafe_root):
                self.git_log.unlink(missing_ok=True)
                self.gh_log.unlink(missing_ok=True)
                os.chmod(unsafe_root, 0o755)
                try:
                    process = self._run(candidate)
                finally:
                    os.chmod(unsafe_root, 0o700)

                self.assertNotEqual(0, process.returncode, process.stdout)
                self.assertIn(
                    "safe root is not an owned non-symlink directory",
                    process.stderr,
                )
                self.assertEqual([], self._git_invocations())
                self.assertEqual([], self._gh_invocations())
                self.assertEqual(set(), self._attestation_directories())


if __name__ == "__main__":
    unittest.main()
