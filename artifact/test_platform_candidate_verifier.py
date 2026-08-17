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

import github_release_observation as github_release
from platform_distribution_contract import (
    CI_WORKFLOW_NAME,
    CI_WORKFLOW_PATH,
    CODEQL_ANALYSIS_CONTRACT,
    CODEQL_ANALYSIS_KEY,
    CODEQL_JOB_CONTRACT,
    CODEQL_TOOL_VERSION,
    CODEQL_WORKFLOW_NAME,
    CODEQL_WORKFLOW_PATH,
    CONSTANT_TIME_JOB_CONTRACT,
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    PRODUCT_VERSION,
    RELEASE_TAG,
    REPOSITORY,
    SOURCE_SECURITY_GATE,
    SOURCE_SECURITY_GATE_KIND,
    SOURCE_SECURITY_GATE_SCHEMA_VERSION,
)


class PlatformCandidateVerifierTests(unittest.TestCase):
    COMMIT = "a" * 40
    SOURCE_PARENT = "b" * 40
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
        cls.stable_notes = (
            cls.repository / "artifact/stable-release-notes.md"
        ).read_text(encoding="utf-8")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve() / "repository"
        artifact = self.root / "artifact"
        artifact.mkdir(parents=True)
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/codeql.yml",
            "artifact/verify-platform-candidate.sh",
            "artifact/python-run.sh",
            "artifact/python-env.sh",
            "artifact/python_bootstrap.py",
            "artifact/bounded_process.py",
            "artifact/evidence_io.py",
            "artifact/git_provenance.py",
            "artifact/github_release_observation.py",
            "artifact/publication_receipt_io.py",
            "artifact/platform_candidate_attestation.py",
            "artifact/platform_distribution_contract.py",
        ):
            source = self.repository / relative
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        (artifact / "results.json").write_text(
            json.dumps({"provenance": {"snapshot_commit": self.SOURCE_PARENT}}) + "\n",
            encoding="ascii",
        )

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
        self.gh_mutate_asset = self.root / "gh-mutate-asset"
        self.gh_mutate_path = self.root / "gh-mutate-path"
        self._write_executable(
            self.fake_bin / "git",
            f"""#!/bin/sh
set -eu
printf '%s\\n' "$*" >> {shlex.quote(str(self.git_log))}
case "$*" in
    *"cat-file -t"*)
        printf 'tag\\n'
        ;;
    *"rev-parse --verify"*)
        printf '%s\\n' {shlex.quote(self.COMMIT)}
        ;;
    *"status --porcelain=v1"*)
        ;;
    *"show -s --format=%ct"*)
        printf '1786700000\n'
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
            f"""#!/bin/sh
set -eu
printf '%s\\n' "$*" >> {shlex.quote(str(self.gh_log))}
case "$1:$2" in
    attestation:verify)
        asset=${{3##*/}}
        /bin/cat {shlex.quote(str(self.gh_outputs))}/"$asset.json"
        if [ -f {shlex.quote(str(self.gh_mutate_asset))} ] && \
           [ "$(/bin/cat {shlex.quote(str(self.gh_mutate_asset))})" = "$asset" ]; then
            printf 'changed during gh verification\\n' >> \
                "$(/bin/cat {shlex.quote(str(self.gh_mutate_path))})"
        fi
        ;;
    *)
        printf 'unexpected fake gh invocation: %s\\n' "$*" >&2
        exit 98
        ;;
esac
""",
        )
        copied_git_policy = artifact / "git_provenance.py"
        copied_git_policy.write_text(
            copied_git_policy.read_text(encoding="utf-8").replace(
                'GIT = "/usr/bin/git"',
                f"GIT = {str(self.fake_bin / 'git')!r}",
            ),
            encoding="utf-8",
        )
        copied_github_policy = artifact / "github_release_observation.py"
        github_policy_source = copied_github_policy.read_text(encoding="utf-8")
        github_policy_source = github_policy_source.replace(
            str(github_release.GITHUB_CLI_PATH),
            str(self.fake_bin / "gh"),
        ).replace(
            github_release.GITHUB_CLI_SHA256,
            hashlib.sha256((self.fake_bin / "gh").read_bytes()).hexdigest(),
        )
        copied_github_policy.write_text(github_policy_source, encoding="utf-8")

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
        (candidate / SOURCE_SECURITY_GATE).write_text(
            json.dumps(self._security_gate(), indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        return candidate

    def _security_gate(self) -> dict[str, object]:
        def workflow(
            *,
            name: str,
            path: str,
            run_id: int,
            jobs: list[dict[str, object]],
        ) -> dict[str, object]:
            source = (self.root / path).read_bytes()
            return {
                "conclusion": "success",
                "event": "push",
                "head_branch": "main",
                "head_sha": self.COMMIT,
                "jobs": jobs,
                "run_attempt": 1,
                "run_id": run_id,
                "status": "completed",
                "workflow_name": name,
                "workflow_path": path,
                "workflow_sha256": hashlib.sha256(source).hexdigest(),
            }

        ct_jobs = [
            {
                "architecture": architecture,
                "conclusion": "success",
                "implementation": implementation,
                "job_id": 100 + index,
                "name": job_name,
                "status": "completed",
            }
            for index, (architecture, implementation, job_name) in enumerate(
                CONSTANT_TIME_JOB_CONTRACT
            )
        ]
        codeql_jobs = [
            {
                "conclusion": "success",
                "job_id": 200 + index,
                "language": language,
                "name": job_name,
                "status": "completed",
            }
            for index, (language, job_name) in enumerate(CODEQL_JOB_CONTRACT)
        ]
        code_scanning_analyses = [
            {
                "analysis_id": 300 + index,
                "analysis_key": CODEQL_ANALYSIS_KEY,
                "category": category,
                "commit_sha": self.COMMIT,
                "error": "",
                "ref": "refs/heads/main",
                "results_count": 0,
                "rules_count": 20 + index,
                "tool": {"name": "CodeQL", "version": CODEQL_TOOL_VERSION},
                "warning": "",
            }
            for index, (_language, category) in enumerate(
                CODEQL_ANALYSIS_CONTRACT
            )
        ]
        return {
            "code_scanning": {
                "analyses": code_scanning_analyses,
                "main_ref": {
                    "commit_sha": self.COMMIT,
                    "ref": "refs/heads/main",
                },
                "open_alerts": [],
            },
            "kind": SOURCE_SECURITY_GATE_KIND,
            "observation_tools": {
                "github_cli": {
                    "name": "gh",
                    "path": "/usr/bin/gh",
                    "sha256": "c" * 64,
                    "version": "gh version 2.94.0 (2026-08-01)",
                }
            },
            "repository": REPOSITORY,
            "schema_version": SOURCE_SECURITY_GATE_SCHEMA_VERSION,
            "source_parent_commit": self.SOURCE_PARENT,
            "tag_commit": self.COMMIT,
            "workflows": {
                "ci": workflow(
                    name=CI_WORKFLOW_NAME,
                    path=CI_WORKFLOW_PATH,
                    run_id=10,
                    jobs=ct_jobs,
                ),
                "codeql": workflow(
                    name=CODEQL_WORKFLOW_NAME,
                    path=CODEQL_WORKFLOW_PATH,
                    run_id=20,
                    jobs=codeql_jobs,
                ),
            },
        }

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
            "githubWorkflowName": "ABI2 stable platform release",
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
        projection_path: pathlib.Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if projection_path is None:
            projection_path = self._projection_path(candidate)
            projection_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(projection_path.parent, 0o700)
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("GIT_")
            and not name.startswith("GH_")
            and name not in github_release.DANGEROUS_GITHUB_ENVIRONMENT
            and name not in github_release.GITHUB_CREDENTIAL_ENVIRONMENT
        }
        environment.update(
            {
                "GH_TOKEN": "fixture-token",
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
            '"--repo"',
            '"--signer-workflow"',
            '"--signer-digest"',
            '"--source-ref"',
            '"--source-digest"',
            '"--deny-self-hosted-runners"',
            '"--format"',
            '"json"',
        ):
            self.assertIn(token, self.verifier_module)
        self.assertIn("refs/remotes/origin/main^{commit}", self.verifier_module)
        self.assertIn(
            '"--untracked-files={\'all\' if include_untracked else \'no\'}"',
            self.verifier_module,
        )
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
            "platform_candidate_attestation.py github-verify",
            self.script,
        )
        self.assertIn("from git_provenance import GIT", self.verifier_module)
        self.assertIn('"core.fsmonitor=false"', self.verifier_module)
        self.assertIn('"core.hooksPath=/dev/null"', self.verifier_module)
        self.assertNotIn("command -v", self.script)
        self.assertIn(
            "platform_candidate_attestation.py validate-raw-root",
            self.script,
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py preflight"),
            self.script.index("platform_candidate_attestation.py checkout-verify"),
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py validate-raw-root"),
            self.script.index("platform_candidate_attestation.py checkout-verify"),
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py snapshot"),
            self.script.index("platform_candidate_attestation.py github-verify"),
        )
        self.assertLess(
            self.script.index("platform_candidate_attestation.py github-verify"),
            self.script.index("platform_candidate_attestation.py verify"),
        )

    def test_tag_preflight_binds_main_current_semver_and_abi2(self) -> None:
        self.assertIn(
            'checkout-verify-release "$commit" "$source_parent"',
            self.workflow,
        )
        self.assertNotIn("git rev-", self.workflow.split("\n  windows:", 1)[0])
        self.assertNotIn("git status", self.workflow.split("\n  windows:", 1)[0])
        self.assertIn(
            "github_release.git_observation_environment()",
            self.verifier_module,
        )
        self.assertIn(
            "test \"$(/usr/bin/jq -r '.package.semver' "
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json)\" "
            f'= "{self.PRODUCT_VERSION}"',
            self.workflow,
        )
        self.assertIn(
            "test \"$(/usr/bin/jq -r '.abi.major' "
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json)\" = \"2\"",
            self.workflow,
        )

    def test_stable_tag_runbook_orders_all_authorities_before_mutation(self) -> None:
        notes = self.stable_notes
        tag_block = notes.split("### Create the two immutable tags at R", 1)[1].split(
            "Before assembling the non-Apple platform distribution", 1
        )[0]
        protection = notes.index("verify-stable-tag-protection")
        local_absent = notes.index("show-ref --verify --quiet")
        remote_absent = notes.index("stable-tag-state absent")
        source_binding = notes.index("R=$(release_git rev-parse")
        pretag = notes.index('pretag-security-readiness "$R" "$S"')
        tag_creation = notes.index("release_tag -a -m")
        apple_push = notes.index('if ! push_exact_tag "$apple_tag"')
        apple_state = notes.index("require_remote_tag_state apple_only")
        platform_push = notes.index('if ! push_exact_tag "$platform_tag"')
        post_push_protection = notes.rindex("verify-stable-tag-protection")
        remote_exact = notes.index("require_remote_tag_state exact")
        self.assertEqual(
            sorted(
                (
                    protection,
                    local_absent,
                    remote_absent,
                    source_binding,
                    pretag,
                    tag_creation,
                    apple_push,
                    apple_state,
                    platform_push,
                    post_push_protection,
                    remote_exact,
                )
            ),
            [
                protection,
                local_absent,
                remote_absent,
                source_binding,
                pretag,
                tag_creation,
                apple_push,
                apple_state,
                platform_push,
                post_push_protection,
                remote_exact,
            ],
        )
        self.assertEqual(2, tag_block.count("verify-stable-tag-protection"))
        for token in (
            "/usr/bin/env -u DEVELOPER_DIR -u SDKROOT -u TOOLCHAINS",
            "-u xcrun_log -u xcrun_verbose -u xcrun_nocache",
            "/usr/bin/python3 -I -S -B -c '",
            'if "GITHUB_TOKEN" in os.environ:',
            'token = required("GH_TOKEN", 4096)',
            'tagger_name = required("RELEASE_TAGGER_NAME", 128,',
            'tagger_email = required("RELEASE_TAGGER_EMAIL", 254,',
            'os.execve(\n    "/bin/sh",',
            '"PATH": "/usr/bin:/bin"',
            '"LANG": "C"',
            '"LC_ALL": "C"',
            "' <<'QPERIAPT_STABLE_TAG_TRANSACTION'",
            "set +x\nset -euf",
            "/usr/bin/printf 'x-access-token:%s'",
            "IFS=' ' read -r pretag_f1 pretag_f2 pretag_f3 pretag_f4",
            'test "$pretag_f1" = PRETAG_SECURITY_READINESS_PASS',
            'test "$pretag_f2" = "tag_commit=$R"',
            'test "$pretag_f3" = "source_parent=$S"',
            "ci_run=",
            "ci_attempt=",
            "codeql_run=",
            "codeql_attempt=",
            "RELEASE_TAGGER_NAME",
            "RELEASE_TAGGER_EMAIL",
            'GIT_COMMITTER_NAME="$RELEASE_TAGGER_NAME"',
            'GIT_COMMITTER_EMAIL="$RELEASE_TAGGER_EMAIL"',
            "git init --bare",
            "push_parent=/private/tmp",
            "qperiapt-stable-tag-push.XXXXXXXX",
            "push_bare_device=$(/usr/bin/stat -f '%d'",
            "push_bare_inode=$(/usr/bin/stat -f '%i'",
            "https://github.com/billlza/q-periapt.git",
            "'+refs/heads/main:refs/remotes/origin/main'",
            "--config-env=http.https://github.com/.extraheader=QPERIAPT_GIT_AUTH",
            "-c http.followRedirects=false -c http.sslVerify=true",
            "GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never",
            "trap 'unset QPERIAPT_GIT_AUTH' EXIT",
            "trap 'unset QPERIAPT_GIT_AUTH; exit 125' HUP INT TERM",
            "stable-tag-state recover",
            "STABLE_TAG_STATE_PASS",
            "IFS=' ' read -r state_f1 state_f2 state_f3 state_f4 state_extra",
            'test "$state_f2" = repository=billlza/q-periapt',
            'case "$remote_state" in absent|apple_only|exact)',
            "require_remote_tag_state apple_only",
            "require_remote_tag_state exact",
            'test "${#S}" -eq 40',
            'case "$S" in \'\'|*[!0-9a-f]*) exit 1 ;; esac',
        ):
            self.assertIn(token, notes)
        self.assertNotIn('/usr/bin/git -C "$release_root" push origin', notes)
        self.assertNotIn("release_git fetch --no-tags origin main", notes)
        self.assertNotIn("export QPERIAPT_GIT_AUTH", notes)
        self.assertNotIn("/usr/bin/env -u BASH_ENV", tag_block)
        self.assertNotIn("$(printf 'x-access-token:%s'", tag_block)
        self.assertNotIn("target/qperiapt-stable-tag-push", tag_block)
        self.assertNotRegex(tag_block, r"(?m)^sh artifact/")
        self.assertNotRegex(tag_block, r"(?m)^chmod ")
        self.assertNotRegex(tag_block, r"(?m).*&& mkdir ")
        self.assertNotRegex(tag_block, r"(?m).*\$\(umask 077 && mktemp ")

    def test_stable_tag_transaction_faults_cannot_reach_mutation(self) -> None:
        tag_block = self.stable_notes.split(
            "### Create the two immutable tags at R", 1
        )[1].split("Before assembling the non-Apple platform distribution", 1)[0]
        shell = tag_block.split("```sh\n", 1)[1].split("\n```", 1)[0]
        self.assertTrue(
            shell.startswith(
                "/usr/bin/env -u DEVELOPER_DIR -u SDKROOT -u TOOLCHAINS \\\n"
                "  -u xcrun_log -u xcrun_verbose -u xcrun_nocache \\\n"
                "  /usr/bin/python3 -I -S -B -c '\nimport os\nimport re\n"
            )
        )
        self.assertIn(
            "' <<'QPERIAPT_STABLE_TAG_TRANSACTION'\nset +x\nset -euf\n",
            shell,
        )
        self.assertTrue(shell.endswith("\nQPERIAPT_STABLE_TAG_TRANSACTION"))
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=shell,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        shellcheck = shutil.which("shellcheck")
        self.assertIsNotNone(shellcheck, "ShellCheck is required for the tag runbook")
        lint = subprocess.run(
            [str(shellcheck), "-s", "sh", "-"],
            input=shell,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, lint.returncode, lint.stdout + lint.stderr)
        launcher, separator, _transaction = shell.partition(
            " <<'QPERIAPT_STABLE_TAG_TRANSACTION'\n"
        )
        self.assertEqual(" <<'QPERIAPT_STABLE_TAG_TRANSACTION'\n", separator)

        # The static test above binds these four fail-closed stages to the real
        # transaction order. Exercise the same fresh-child boundary for every
        # stage and prove that neither startup injection nor mutation is reached,
        # even when the trusted parent itself has ordinary xtrace enabled.
        for failed_stage in ("authority", "absence", "root", "pretag"):
            with (
                self.subTest(failed_stage=failed_stage),
                tempfile.TemporaryDirectory() as temporary,
            ):
                sentinel = pathlib.Path(temporary) / "mutation-sentinel"
                startup_sentinel = pathlib.Path(temporary) / "startup-sentinel"
                startup = pathlib.Path(temporary) / "hostile-startup.sh"
                secret = "fixture-gh-token-must-not-appear"
                startup.write_text(
                    f"/bin/touch {shlex.quote(str(startup_sentinel))}\n"
                    "/usr/bin/printf '%s\\n' \"$GH_TOKEN\" >&2\n",
                    encoding="utf-8",
                )
                stages = ("authority", "absence", "root", "pretag")
                commands = [
                    "/usr/bin/false" if stage == failed_stage else "/usr/bin/true"
                    for stage in stages
                ]
                hostile_body = (
                    f"/bin/touch {shlex.quote(str(startup_sentinel))}; "
                    "/usr/bin/printf '%s\\n' \"$GH_TOKEN\" >&2; return 97"
                )
                harness = (
                    f"test() {{ {hostile_body}; }}\n"
                    f"printf() {{ {hostile_body}; }}\n"
                    f"cd() {{ {hostile_body}; }}\n"
                    f"umask() {{ {hostile_body}; }}\n"
                    "export -f test printf cd umask\n"
                    f"BASH_ENV={shlex.quote(str(startup))}\n"
                    "ENV=$BASH_ENV\nPS4=+trusted-parent-trace\n"
                    "export BASH_ENV ENV SHELLOPTS BASHOPTS PS4\nset -x\n"
                    + launcher
                    + " <<'QPERIAPT_STABLE_TAG_TRANSACTION'\n"
                    "set +x\nset -euf\n"
                    "test \"$PWD\" = \"$(/bin/pwd -P)\"\n"
                    "printf '%s\\n' CHILD_BUILTIN_BOUNDARY_PASS\n"
                    "cd .\n"
                    "umask 077\n"
                    + "\n".join(commands)
                    + f"\n/bin/touch {shlex.quote(str(sentinel))}\n"
                    "QPERIAPT_STABLE_TAG_TRANSACTION\n"
                )
                environment = os.environ.copy()
                environment["GH_TOKEN"] = secret
                environment["RELEASE_TAGGER_NAME"] = "Release Operator"
                environment["RELEASE_TAGGER_EMAIL"] = "release@example.test"
                environment.pop("GITHUB_TOKEN", None)
                environment["DEVELOPER_DIR"] = "/private/tmp/hostile-developer"
                environment["SDKROOT"] = "/private/tmp/hostile-sdk"
                environment["TOOLCHAINS"] = "hostile-toolchain"
                environment["xcrun_log"] = "1"
                environment["xcrun_verbose"] = "1"
                environment["xcrun_nocache"] = "1"
                result = subprocess.run(
                    ["/bin/bash", "-c", harness],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(sentinel.exists())
                self.assertFalse(startup_sentinel.exists())
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertIn("CHILD_BUILTIN_BOUNDARY_PASS", result.stdout)

    def test_stable_tag_launcher_rejects_untrusted_release_environment(self) -> None:
        tag_block = self.stable_notes.split(
            "### Create the two immutable tags at R", 1
        )[1].split("Before assembling the non-Apple platform distribution", 1)[0]
        shell = tag_block.split("```sh\n", 1)[1].split("\n```", 1)[0]
        launcher, separator, _transaction = shell.partition(
            " <<'QPERIAPT_STABLE_TAG_TRANSACTION'\n"
        )
        self.assertEqual(" <<'QPERIAPT_STABLE_TAG_TRANSACTION'\n", separator)

        cases = (
            ("missing-token", {}, ("GH_TOKEN",)),
            ("ambiguous-token", {"GITHUB_TOKEN": "ambiguous-private-token"}, ()),
            ("control-token", {"GH_TOKEN": "fixture-private-token\n"}, ()),
            ("oversized-token", {"GH_TOKEN": "t" * 4097}, ()),
            ("unsafe-name", {"RELEASE_TAGGER_NAME": "Release;Operator"}, ()),
            ("unsafe-email", {"RELEASE_TAGGER_EMAIL": "a@@example.test"}, ()),
        )
        for name, updates, removals in cases:
            with (
                self.subTest(name=name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                sentinel = pathlib.Path(temporary) / "child-sentinel"
                environment = os.environ.copy()
                environment.update(
                    {
                        "GH_TOKEN": "fixture-private-token",
                        "RELEASE_TAGGER_NAME": "Release Operator",
                        "RELEASE_TAGGER_EMAIL": "release@example.test",
                    }
                )
                environment.pop("GITHUB_TOKEN", None)
                environment.update(updates)
                for key in removals:
                    environment.pop(key, None)
                command = (
                    launcher
                    + " <<'QPERIAPT_STABLE_TAG_TRANSACTION'\n"
                    "set +x\nset -euf\n"
                    f"/bin/touch {shlex.quote(str(sentinel))}\n"
                    "QPERIAPT_STABLE_TAG_TRANSACTION\n"
                )
                result = subprocess.run(
                    ["/bin/sh", "-c", command],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(sentinel.exists())
                combined = result.stdout + result.stderr
                self.assertNotIn("fixture-private-token", combined)
                self.assertNotIn("ambiguous-private-token", combined)

    def test_platform_release_identity_selects_stable_r1_receipt(self) -> None:
        release_tag = self.RELEASE_TAG
        self.assertIn(
            'release_ref = f"refs/tags/{RELEASE_TAG}"',
            self.verifier_module,
        )
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
            self.stable_notes,
        )
        self.assertIn(
            "target/abi2-platform-candidate-inputs",
            self.stable_notes,
        )
        self.assertIn(
            "target/abi2-platform-candidate-projections",
            self.stable_notes,
        )
        self.assertIn(
            "target/abi2-platform-candidate-verification/raw",
            self.stable_notes,
        )
        self.assertNotIn(
            "candidate_dir=/absolute/path/to/stable-platform-candidate",
            self.stable_notes,
        )
        for fixed_apple_root in (
            "target/qperiapt-apple-release-worktrees",
            "target/qperiapt-apple-release-verification",
        ):
            self.assertIn(fixed_apple_root, self.stable_notes)
        self.assertNotIn(
            "completed=/absolute/path/to/apple-release/completed.json",
            self.stable_notes,
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
            (*self.ASSETS, "CANDIDATE_SHA256SUMS", SOURCE_SECURITY_GATE),
            self.SUBJECTS,
        )
        self.assertIn('list(arguments) == ["subject-names"]', self.verifier_module)
        self.assertIn(
            "for subject in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:",
            self.verifier_module,
        )
        self.assertIn(
            "assets={len(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS)}",
            self.verifier_module,
        )

        subject_start = self.workflow.index("          subject-path: |\n")
        subject_end = self.workflow.index("\n      - uses:", subject_start)
        subject_lines = self.workflow[subject_start:subject_end].splitlines()[1:]
        expected_subjects = {
            f"candidate/{asset}"
            for asset in self.SUBJECTS
        }
        actual_subjects = [line.strip() for line in subject_lines]
        self.assertEqual(len(self.SUBJECTS), len(actual_subjects))
        self.assertEqual(expected_subjects, set(actual_subjects))

    def test_valid_candidate_executes_exact_attestation_verifications(self) -> None:
        candidate = self._candidate("valid")
        self._install_valid_gh_outputs(candidate)
        process = self._run(candidate)
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertIn(
            "ABI2_PLATFORM_CANDIDATE_ATTESTATION_VERIFY_PASS "
            f"assets={len(self.SUBJECTS)} commit={self.COMMIT}",
            process.stdout,
        )

        invocations = self._gh_invocations()
        attestation_invocations = invocations
        self.assertEqual(len(self.SUBJECTS), len(attestation_invocations))
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
                "security_gate",
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
        security_gate_bytes = (candidate / SOURCE_SECURITY_GATE).read_bytes()
        self.assertEqual(
            hashlib.sha256(security_gate_bytes).hexdigest(),
            projection["security_gate"]["receipt_sha256"],
        )
        self.assertEqual(self.COMMIT, projection["security_gate"]["tag_commit"])
        self.assertEqual(
            self.SOURCE_PARENT,
            projection["security_gate"]["source_parent_commit"],
        )
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

        def fail_security_gate(candidate: pathlib.Path) -> None:
            path = candidate / SOURCE_SECURITY_GATE
            value = json.loads(path.read_bytes())
            value["workflows"]["ci"]["jobs"][0]["conclusion"] = "failure"
            path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")

        mutations = (
            ("tampered-checksum", tamper),
            ("extra-file", add_extra),
            ("symlink", add_symlink),
            ("missing-file", remove_asset),
            ("noncanonical-sums", reorder_sums),
            ("failed-security-gate", fail_security_gate),
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

        self.gh_mutate_asset.write_text(self.SUBJECTS[0], encoding="ascii")
        self.gh_mutate_path.write_text(
            str(candidate / self.ASSETS[0]),
            encoding="utf-8",
        )
        process = self._run(candidate)

        self.assertNotEqual(0, process.returncode, process.stdout)
        self.assertEqual(len(self.SUBJECTS), len(self._gh_invocations()))
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
