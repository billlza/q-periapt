from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

import platform_candidate_attestation as candidate_attestation
from platform_candidate_attestation import (
    CANDIDATE_SNAPSHOT_NAME,
    PROJECTION_NAME,
    CandidateAttestationError,
    load_candidate_snapshot,
    snapshot_candidate,
    write_candidate_snapshot,
)
from platform_distribution_contract import (
    CANDIDATE_SUMS,
    CODEQL_ANALYSIS_CONTRACT,
    CODEQL_ANALYSIS_KEY,
    CODEQL_JOB_CONTRACT,
    CODEQL_TOOL_VERSION,
    CODEQL_WORKFLOW_NAME,
    CODEQL_WORKFLOW_PATH,
    CONSTANT_TIME_JOB_CONTRACT,
    CI_WORKFLOW_NAME,
    CI_WORKFLOW_PATH,
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    RELEASE_TAG,
    SOURCE_SECURITY_GATE,
    validate_source_security_gate,
)


class PlatformCandidateAttestationTests(unittest.TestCase):
    TAG_COMMIT = "a" * 40
    SOURCE_PARENT = "b" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.candidate_root = self.root / "abi2-platform-candidate-inputs"
        self.verification_root = self.root / "abi2-platform-candidate-verification"
        self.raw_root = self.verification_root / "raw"
        self.projection_root = self.root / "abi2-platform-candidate-projections"
        for path in (self.candidate_root, self.raw_root, self.projection_root):
            path.mkdir(parents=True, mode=0o700)
            os.chmod(path, 0o700)
        os.chmod(self.verification_root, 0o700)
        for attribute, value in (
            ("CANDIDATE_INPUT_ROOT", self.candidate_root),
            ("CANDIDATE_VERIFICATION_ROOT", self.verification_root),
            ("CANDIDATE_RAW_ROOT", self.raw_root),
            ("CANDIDATE_PROJECTION_ROOT", self.projection_root),
        ):
            patcher = mock.patch.object(candidate_attestation, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _candidate(self, name: str) -> pathlib.Path:
        candidate = self.candidate_root / name
        candidate.mkdir()
        checksums: list[tuple[str, str]] = []
        for asset in PLATFORM_CANDIDATE_ASSETS:
            data = f"exact fixture bytes for {asset}\n".encode("ascii")
            (candidate / asset).write_bytes(data)
            checksums.append((asset, hashlib.sha256(data).hexdigest()))
        (candidate / CANDIDATE_SUMS).write_text(
            "".join(
                f"{digest}  {asset}\n" for asset, digest in sorted(checksums)
            ),
            encoding="ascii",
        )
        (candidate / SOURCE_SECURITY_GATE).write_text("{}\n", encoding="ascii")
        return candidate

    def _private_output_paths(self, name: str) -> tuple[pathlib.Path, pathlib.Path]:
        raw_parent = self.raw_root / name
        projection_parent = self.projection_root / name
        raw_parent.mkdir(mode=0o700)
        projection_parent.mkdir(mode=0o700)
        os.chmod(raw_parent, 0o700)
        os.chmod(projection_parent, 0o700)
        return (
            raw_parent / CANDIDATE_SNAPSHOT_NAME,
            projection_parent / PROJECTION_NAME,
        )

    def test_current_contract_is_the_exact_six_subject_tuple(self) -> None:
        self.assertEqual(4, len(PLATFORM_CANDIDATE_ASSETS))
        self.assertEqual(
            (*PLATFORM_CANDIDATE_ASSETS, CANDIDATE_SUMS, SOURCE_SECURITY_GATE),
            PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
        )
        self.assertEqual(6, len(set(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS)))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = candidate_attestation._main(["subject-names"])
        self.assertEqual(0, status)
        self.assertEqual(
            list(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
            output.getvalue().splitlines(),
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = candidate_attestation._main(["release-tag"])
        self.assertEqual(0, status)
        self.assertEqual(f"{RELEASE_TAG}\n", output.getvalue())

    def _workflow_run(
        self,
        run_id: int,
        *,
        name: str,
        path: str,
        attempt: int = 1,
    ) -> dict[str, object]:
        return {
            "conclusion": "success",
            "event": "push",
            "head_branch": "main",
            "head_sha": self.TAG_COMMIT,
            "html_url": "https://example.invalid/private-run",
            "id": run_id,
            "name": name,
            "path": path,
            "run_attempt": attempt,
            "runner_hint": "/Users/operator/runner",
            "status": "completed",
        }

    @staticmethod
    def _jobs(
        run_id: int,
        attempt: int,
        names: list[str],
        *,
        first_id: int,
    ) -> dict[str, object]:
        jobs = [
            {
                "conclusion": "success",
                "html_url": "https://example.invalid/private-job",
                "id": first_id + index,
                "name": name,
                "run_attempt": attempt,
                "run_id": run_id,
                "runner_name": "/Users/operator/runner",
                "status": "completed",
            }
            for index, name in enumerate(names)
        ]
        return {"jobs": jobs, "total_count": len(jobs)}

    def _code_scanning_analysis(
        self,
        analysis_id: int,
        language: str,
        *,
        commit_sha: str | None = None,
    ) -> dict[str, object]:
        return {
            "analysis_key": CODEQL_ANALYSIS_KEY,
            "category": f"/language:{language}",
            "commit_sha": self.TAG_COMMIT if commit_sha is None else commit_sha,
            "created_at": "2026-08-15T00:00:00Z",
            "environment": "{}",
            "error": "",
            "id": analysis_id,
            "ref": "refs/heads/main",
            "results_count": 0,
            "rules_count": 20 + analysis_id % 10,
            "tool": {
                "guid": None,
                "name": "CodeQL",
                "version": CODEQL_TOOL_VERSION,
            },
            "url": "https://api.github.com/private-analysis",
            "warning": "",
        }

    def _security_gate_inputs(
        self,
    ) -> tuple[object, object, object, object, object, object, object]:
        ci_runs = {
            "total_count": 2,
            "workflow_runs": [
                self._workflow_run(
                    10,
                    name=CI_WORKFLOW_NAME,
                    path=CI_WORKFLOW_PATH,
                ),
                self._workflow_run(
                    20,
                    name=CI_WORKFLOW_NAME,
                    path=CI_WORKFLOW_PATH,
                    attempt=2,
                ),
            ],
        }
        ci_names = [name for _architecture, _implementation, name in CONSTANT_TIME_JOB_CONTRACT]
        ci_jobs = self._jobs(20, 2, [*ci_names, "Unrelated successful CI job"], first_id=100)
        codeql_runs = {
            "total_count": 1,
            "workflow_runs": [
                self._workflow_run(
                    30,
                    name=CODEQL_WORKFLOW_NAME,
                    path=CODEQL_WORKFLOW_PATH,
                    attempt=3,
                )
            ],
        }
        codeql_jobs = self._jobs(
            30,
            3,
            [name for _language, name in CODEQL_JOB_CONTRACT],
            first_id=200,
        )
        main_ref = {
            "node_id": "private-node-id",
            "object": {
                "sha": self.TAG_COMMIT,
                "type": "commit",
                "url": "https://api.github.com/private-commit",
            },
            "ref": "refs/heads/main",
            "url": "https://api.github.com/private-ref",
        }
        analyses = [
            self._code_scanning_analysis(300 + index, language)
            for index, (language, _category) in enumerate(
                CODEQL_ANALYSIS_CONTRACT
            )
        ]
        analyses.append(
            self._code_scanning_analysis(
                250,
                "actions",
                commit_sha="f" * 40,
            )
        )
        open_alerts: list[object] = []
        return (
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            main_ref,
            analyses,
            open_alerts,
        )

    def test_security_gate_selects_highest_exact_runs_and_sanitizes_projection(
        self,
    ) -> None:
        gate = candidate_attestation.build_source_security_gate(
            *self._security_gate_inputs(),
            expected_tag_commit=self.TAG_COMMIT,
            expected_source_parent_commit=self.SOURCE_PARENT,
            ci_workflow_sha256="c" * 64,
            codeql_workflow_sha256="d" * 64,
            github_cli_sha256="e" * 64,
            github_cli_version="gh version 2.94.0 (2026-08-01)",
        )

        validate_source_security_gate(
            gate,
            expected_tag_commit=self.TAG_COMMIT,
            expected_source_parent_commit=self.SOURCE_PARENT,
            expected_ci_workflow_sha256="c" * 64,
            expected_codeql_workflow_sha256="d" * 64,
        )
        self.assertEqual(20, gate["workflows"]["ci"]["run_id"])
        self.assertEqual(2, gate["workflows"]["ci"]["run_attempt"])
        self.assertEqual(30, gate["workflows"]["codeql"]["run_id"])
        self.assertEqual(6, len(gate["workflows"]["codeql"]["jobs"]))
        self.assertEqual(
            self.TAG_COMMIT,
            gate["code_scanning"]["main_ref"]["commit_sha"],
        )
        self.assertEqual(
            300,
            gate["code_scanning"]["analyses"][0]["analysis_id"],
        )
        self.assertEqual([], gate["code_scanning"]["open_alerts"])
        serialized = json.dumps(gate, sort_keys=True)
        for forbidden in (
            "api.github.com",
            "created_at",
            "environment",
            "html_url",
            "runner_name",
            "/Users/",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_security_gate_rejects_missing_failed_ambiguous_or_partial_jobs(self) -> None:
        for mutation in (
            "failed-ct",
            "missing-codeql",
            "duplicate-codeql",
            "partial-page",
            "oversized-run-id",
            "boolean-job-id",
            "later-ci-failed-run",
            "later-ci-in-progress-run",
            "later-codeql-failed-run",
            "later-codeql-in-progress-run",
            "analysis-nonzero",
            "analysis-error",
            "analysis-warning",
            "analysis-full-page",
            "missing-analysis",
            "duplicate-analysis-id",
            "wrong-analysis-sha",
            "wrong-analysis-ref",
            "wrong-analysis-tool",
            "wrong-analysis-tool-version",
            "wrong-analysis-category",
            "zero-analysis-rules",
            "wrong-main-ref-sha",
            "open-alert",
        ):
            with self.subTest(mutation=mutation):
                (
                    ci_runs,
                    ci_jobs,
                    codeql_runs,
                    codeql_jobs,
                    main_ref,
                    analyses,
                    open_alerts,
                ) = copy.deepcopy(self._security_gate_inputs())
                if mutation == "failed-ct":
                    ci_jobs["jobs"][0]["conclusion"] = "failure"
                elif mutation == "missing-codeql":
                    codeql_jobs["jobs"].pop()
                    codeql_jobs["total_count"] -= 1
                elif mutation == "duplicate-codeql":
                    codeql_jobs["jobs"][1]["name"] = codeql_jobs["jobs"][0]["name"]
                elif mutation == "partial-page":
                    codeql_jobs["total_count"] += 1
                elif mutation == "oversized-run-id":
                    codeql_runs["workflow_runs"][0]["id"] = (
                        candidate_attestation.MAX_RUN_ID + 1
                    )
                elif mutation == "boolean-job-id":
                    ci_jobs["jobs"][0]["id"] = True
                elif mutation.startswith("later-ci-"):
                    later = self._workflow_run(
                        21,
                        name=CI_WORKFLOW_NAME,
                        path=CI_WORKFLOW_PATH,
                    )
                    if mutation == "later-ci-failed-run":
                        later["conclusion"] = "failure"
                    else:
                        later["status"] = "in_progress"
                        later["conclusion"] = None
                    ci_runs["workflow_runs"].append(later)
                    ci_runs["total_count"] += 1
                elif mutation.startswith("later-codeql-"):
                    later = self._workflow_run(
                        31,
                        name=CODEQL_WORKFLOW_NAME,
                        path=CODEQL_WORKFLOW_PATH,
                    )
                    if mutation == "later-codeql-failed-run":
                        later["conclusion"] = "failure"
                    else:
                        later["status"] = "in_progress"
                        later["conclusion"] = None
                    codeql_runs["workflow_runs"].append(later)
                    codeql_runs["total_count"] += 1
                elif mutation == "analysis-nonzero":
                    analyses[0]["results_count"] = 1
                elif mutation == "analysis-error":
                    analyses[0]["error"] = "analysis failed"
                elif mutation == "analysis-warning":
                    analyses[0]["warning"] = "partial extraction"
                elif mutation == "analysis-full-page":
                    while len(analyses) < 100:
                        analyses.append(
                            self._code_scanning_analysis(
                                1_000 + len(analyses),
                                "actions",
                            )
                        )
                elif mutation == "missing-analysis":
                    analyses.pop(5)
                elif mutation == "duplicate-analysis-id":
                    analyses[1]["id"] = analyses[0]["id"]
                elif mutation == "wrong-analysis-sha":
                    analyses[0]["commit_sha"] = "e" * 40
                elif mutation == "wrong-analysis-ref":
                    analyses[0]["ref"] = "refs/pull/26/merge"
                elif mutation == "wrong-analysis-tool":
                    analyses[0]["tool"]["name"] = "Other"
                elif mutation == "wrong-analysis-tool-version":
                    analyses[0]["tool"]["version"] = "2.26.1"
                elif mutation == "wrong-analysis-category":
                    analyses[0]["category"] = "/language:ruby"
                elif mutation == "zero-analysis-rules":
                    analyses[0]["rules_count"] = 0
                elif mutation == "wrong-main-ref-sha":
                    main_ref["object"]["sha"] = "e" * 40
                else:
                    open_alerts.append({"number": 1})
                with self.assertRaises(CandidateAttestationError):
                    candidate_attestation.build_source_security_gate(
                        ci_runs,
                        ci_jobs,
                        codeql_runs,
                        codeql_jobs,
                        main_ref,
                        analyses,
                        open_alerts,
                        expected_tag_commit=self.TAG_COMMIT,
                        expected_source_parent_commit=self.SOURCE_PARENT,
                        ci_workflow_sha256="c" * 64,
                        codeql_workflow_sha256="d" * 64,
                        github_cli_sha256="e" * 64,
                        github_cli_version="gh version 2.94.0 (2026-08-01)",
                    )

    def test_live_security_gate_uses_one_resampled_hosted_cli_projection(
        self,
    ) -> None:
        (
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            main_ref,
            analyses,
            open_alerts,
        ) = self._security_gate_inputs()
        tool = candidate_attestation.WorkflowToolIdentity(
            path="/usr/bin/gh",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o755,
            uid=0,
            link_count=1,
            size=10,
            sha256="e" * 64,
        )
        sample = (
            ci_runs,
            codeql_runs,
            ci_jobs,
            codeql_jobs,
            main_ref,
            analyses,
            open_alerts,
        )
        responses = [b"gh version 2.94.0 (2026-08-01)\n"] + [
            json.dumps(value).encode("ascii")
            for value in (*sample, *copy.deepcopy(sample))
        ]
        capture = mock.Mock(side_effect=responses)
        output = self.root / SOURCE_SECURITY_GATE
        with (
            mock.patch.object(
                candidate_attestation,
                "_source_parent_from_results",
                return_value=self.SOURCE_PARENT,
            ),
            mock.patch.object(
                candidate_attestation,
                "_workflow_github_environment",
                return_value={"GH_TOKEN": "fixture-token"},
            ),
            mock.patch.object(
                candidate_attestation,
                "_workflow_github_cli_identity",
                return_value=tool,
            ),
            mock.patch.object(
                candidate_attestation,
                "_capture_workflow_github_cli",
                capture,
            ),
            mock.patch.object(
                candidate_attestation,
                "_workflow_sha256",
                side_effect=("c" * 64, "d" * 64),
            ),
            mock.patch.object(
                candidate_attestation,
                "_write_public_gate_noreplace",
                return_value="f" * 64,
            ) as writer,
        ):
            digest = candidate_attestation.assemble_live_source_security_gate(
                self.TAG_COMMIT,
                self.SOURCE_PARENT,
                output,
                source_environment={"GH_TOKEN": "fixture-token"},
            )

        self.assertEqual("f" * 64, digest)
        self.assertEqual(15, capture.call_count)
        for api_call in capture.call_args_list[1:]:
            arguments = api_call.args[1]
            self.assertEqual("api", arguments[0])
            self.assertIn("Accept: application/vnd.github+json", arguments)
            self.assertIn(
                "X-GitHub-Api-Version: "
                f"{candidate_attestation.github_release.GITHUB_API_VERSION}",
                arguments,
            )
        self.assertIn("actions/workflows/ci.yml/runs?", capture.call_args_list[1].args[1][-1])
        self.assertIn("actions/workflows/codeql.yml/runs?", capture.call_args_list[2].args[1][-1])
        self.assertIn("/runs/20/attempts/2/jobs?", capture.call_args_list[3].args[1][-1])
        self.assertIn("/runs/30/attempts/3/jobs?", capture.call_args_list[4].args[1][-1])
        self.assertIn("/git/ref/heads/main", capture.call_args_list[5].args[1][-1])
        self.assertIn("tool_name=CodeQL", capture.call_args_list[6].args[1][-1])
        self.assertIn("state=open", capture.call_args_list[7].args[1][-1])
        gate = writer.call_args.args[1]
        self.assertEqual("e" * 64, gate["observation_tools"]["github_cli"]["sha256"])
        self.assertEqual(20, gate["workflows"]["ci"]["run_id"])

    def test_live_security_gate_rejects_second_sample_drift(self) -> None:
        inputs = self._security_gate_inputs()
        ci_runs, ci_jobs, codeql_runs, codeql_jobs, main_ref, analyses, alerts = inputs
        selected_ci = ci_runs["workflow_runs"][1]
        selected_codeql = codeql_runs["workflow_runs"][0]
        before = (
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            main_ref,
            analyses,
            alerts,
            selected_ci,
            selected_codeql,
        )
        after = copy.deepcopy(before)
        after[5][0]["created_at"] = "2026-08-15T00:00:01Z"
        tool = candidate_attestation.WorkflowToolIdentity(
            path="/usr/bin/gh",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o755,
            uid=0,
            link_count=1,
            size=10,
            sha256="e" * 64,
        )
        with (
            mock.patch.object(
                candidate_attestation,
                "_source_parent_from_results",
                return_value=self.SOURCE_PARENT,
            ),
            mock.patch.object(
                candidate_attestation,
                "_workflow_github_environment",
                return_value={"GH_TOKEN": "fixture-token"},
            ),
            mock.patch.object(
                candidate_attestation,
                "_workflow_github_cli_identity",
                return_value=tool,
            ),
            mock.patch.object(
                candidate_attestation,
                "_capture_workflow_github_cli",
                return_value=b"gh version 2.94.0 (2026-08-01)\n",
            ),
            mock.patch.object(
                candidate_attestation,
                "_query_source_security_api",
                side_effect=(before, after),
            ),
            mock.patch.object(
                candidate_attestation,
                "_write_public_gate_noreplace",
            ) as writer,
            self.assertRaisesRegex(
                CandidateAttestationError,
                "live source-security observations changed between samples",
            ),
        ):
            candidate_attestation.assemble_live_source_security_gate(
                self.TAG_COMMIT,
                self.SOURCE_PARENT,
                self.root / SOURCE_SECURITY_GATE,
                source_environment={"GH_TOKEN": "fixture-token"},
            )
        writer.assert_not_called()

    def test_live_security_gate_rejects_malformed_commits_before_io(self) -> None:
        for label, tag_commit, source_parent in (
            ("R", "not-a-commit", self.SOURCE_PARENT),
            ("S", self.TAG_COMMIT, "A" * 40),
        ):
            with self.subTest(commit=label):
                with (
                    mock.patch.object(
                        candidate_attestation,
                        "_source_parent_from_results",
                    ) as results_reader,
                    mock.patch.object(
                        candidate_attestation,
                        "_workflow_github_environment",
                    ) as environment_builder,
                    mock.patch.object(
                        candidate_attestation,
                        "_workflow_github_cli_identity",
                    ) as tool_probe,
                    mock.patch.object(
                        candidate_attestation,
                        "_capture_workflow_github_cli",
                    ) as capture,
                    mock.patch.object(
                        candidate_attestation,
                        "_query_source_security_api",
                    ) as api_query,
                    mock.patch.object(
                        candidate_attestation,
                        "_workflow_sha256",
                    ) as workflow_hash,
                    mock.patch.object(
                        candidate_attestation,
                        "_write_public_gate_noreplace",
                    ) as writer,
                    self.assertRaisesRegex(
                        CandidateAttestationError,
                        rf"source security gate {label} is malformed",
                    ),
                ):
                    candidate_attestation.assemble_live_source_security_gate(
                        tag_commit,
                        source_parent,
                        self.root / SOURCE_SECURITY_GATE,
                        source_environment={"GH_TOKEN": "fixture-token"},
                    )
                for operation in (
                    results_reader,
                    environment_builder,
                    tool_probe,
                    capture,
                    api_query,
                    workflow_hash,
                    writer,
                ):
                    operation.assert_not_called()

    def test_pretag_security_readiness_double_samples_exact_runs(self) -> None:
        (
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            main_ref,
            analyses,
            open_alerts,
        ) = self._security_gate_inputs()
        tool = candidate_attestation.github_release.GitHubCliIdentity(
            path="/pinned/gh",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o755,
            uid=os.geteuid(),
            link_count=1,
            size=10,
            sha256="e" * 64,
        )
        sample = [
            ci_runs,
            codeql_runs,
            ci_jobs,
            codeql_jobs,
            main_ref,
            analyses,
            open_alerts,
        ]
        responses = [
            json.dumps(value).encode("ascii")
            for value in (*sample, *copy.deepcopy(sample))
        ]
        capture = mock.Mock(side_effect=responses)
        with (
            mock.patch.object(
                candidate_attestation,
                "_source_parent_from_results",
                return_value=self.SOURCE_PARENT,
            ),
            mock.patch.object(
                candidate_attestation,
                "validate_tag_source_currentness",
            ) as currentness,
            mock.patch.object(
                candidate_attestation.github_release,
                "github_cli_environment",
                return_value={"GH_TOKEN": "fixture-token"},
            ),
            mock.patch.object(
                candidate_attestation.github_release,
                "select_github_cli",
                return_value=tool,
            ),
            mock.patch.object(
                candidate_attestation.github_release,
                "capture_github_cli",
                capture,
            ),
        ):
            observed = candidate_attestation.verify_pretag_security_readiness(
                self.TAG_COMMIT,
                self.SOURCE_PARENT,
                source_environment={"GH_TOKEN": "fixture-token"},
            )

        self.assertEqual((20, 2, 30, 3, "e" * 64), observed)
        self.assertEqual(14, capture.call_count)
        for api_call in capture.call_args_list:
            arguments = api_call.args[1]
            self.assertEqual("api", arguments[0])
            self.assertIn("Accept: application/vnd.github+json", arguments)
            self.assertIn(
                "X-GitHub-Api-Version: "
                f"{candidate_attestation.github_release.GITHUB_API_VERSION}",
                arguments,
            )
        currentness.assert_called_once_with(self.SOURCE_PARENT)

    def test_pretag_security_readiness_rejects_second_sample_drift(self) -> None:
        (
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            main_ref,
            analyses,
            open_alerts,
        ) = self._security_gate_inputs()
        changed_analyses = copy.deepcopy(analyses)
        changed_analyses[0]["created_at"] = "2026-08-15T00:00:01Z"
        responses = [
            json.dumps(value).encode("ascii")
            for value in (
                ci_runs,
                codeql_runs,
                ci_jobs,
                codeql_jobs,
                main_ref,
                analyses,
                open_alerts,
                ci_runs,
                codeql_runs,
                ci_jobs,
                codeql_jobs,
                main_ref,
                changed_analyses,
                open_alerts,
            )
        ]
        tool = candidate_attestation.github_release.GitHubCliIdentity(
            path="/pinned/gh",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o755,
            uid=os.geteuid(),
            link_count=1,
            size=10,
            sha256="e" * 64,
        )
        with (
            mock.patch.object(
                candidate_attestation,
                "_source_parent_from_results",
                return_value=self.SOURCE_PARENT,
            ),
            mock.patch.object(candidate_attestation, "validate_tag_source_currentness"),
            mock.patch.object(
                candidate_attestation.github_release,
                "github_cli_environment",
                return_value={"GH_TOKEN": "fixture-token"},
            ),
            mock.patch.object(
                candidate_attestation.github_release,
                "select_github_cli",
                return_value=tool,
            ),
            mock.patch.object(
                candidate_attestation.github_release,
                "capture_github_cli",
                side_effect=responses,
            ),
            self.assertRaises(CandidateAttestationError),
        ):
            candidate_attestation.verify_pretag_security_readiness(
                self.TAG_COMMIT,
                self.SOURCE_PARENT,
                source_environment={"GH_TOKEN": "fixture-token"},
            )

    def test_security_gate_writer_is_public_exclusive_and_deterministic(
        self,
    ) -> None:
        gate = candidate_attestation.build_source_security_gate(
            *self._security_gate_inputs(),
            expected_tag_commit=self.TAG_COMMIT,
            expected_source_parent_commit=self.SOURCE_PARENT,
            ci_workflow_sha256="c" * 64,
            codeql_workflow_sha256="d" * 64,
            github_cli_sha256="e" * 64,
            github_cli_version="gh version 2.94.0 (2026-08-01)",
        )
        output_parent = self.root / "workflow-candidate"
        output_parent.mkdir(mode=0o700)
        output = output_parent / SOURCE_SECURITY_GATE
        with mock.patch.object(
            candidate_attestation,
            "WORKFLOW_CANDIDATE_ROOT",
            output_parent,
        ):
            digest = candidate_attestation._write_public_gate_noreplace(
                output,
                gate,
            )
            self.assertEqual(
                hashlib.sha256(output.read_bytes()).hexdigest(),
                digest,
            )
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            with self.assertRaises(CandidateAttestationError):
                candidate_attestation._write_public_gate_noreplace(output, gate)
            committed = candidate_attestation.PublicationReceiptCommittedError(
                "fixture committed gate",
                leaf=SOURCE_SECURITY_GATE,
                digest="f" * 64,
            )
            with (
                mock.patch.object(
                    candidate_attestation,
                    "write_private_bytes_noreplace_at",
                    side_effect=committed,
                ),
                self.assertRaises(
                    candidate_attestation.PublicationReceiptCommittedError
                ) as caught,
            ):
                candidate_attestation._write_public_gate_noreplace(output, gate)
            self.assertIs(committed, caught.exception)

    def test_offline_security_gate_cli_accepts_all_seven_observations(self) -> None:
        inputs = self._security_gate_inputs()
        fixture_paths: list[pathlib.Path] = []
        for index, value in enumerate(inputs):
            path = self.root / f"security-api-{index}.json"
            path.write_text(json.dumps(value), encoding="ascii")
            fixture_paths.append(path)
        output_parent = self.root / "offline-candidate"
        output_parent.mkdir(mode=0o700)
        os.chmod(output_parent, 0o700)
        output = output_parent / SOURCE_SECURITY_GATE
        command = [
            "security-gate",
            *(str(path) for path in fixture_paths),
            self.TAG_COMMIT,
            self.SOURCE_PARENT,
            str(output),
            "e" * 64,
            "gh version 2.94.0 (2026-08-01)",
        ]
        stdout = io.StringIO()
        with (
            mock.patch.object(
                candidate_attestation,
                "_source_parent_from_results",
                return_value=self.SOURCE_PARENT,
            ),
            mock.patch.object(
                candidate_attestation,
                "_workflow_sha256",
                side_effect=("c" * 64, "d" * 64),
            ),
            mock.patch.object(
                candidate_attestation,
                "WORKFLOW_CANDIDATE_ROOT",
                output_parent,
            ),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(0, candidate_attestation._main(command))
        gate = json.loads(output.read_text(encoding="ascii"))
        validate_source_security_gate(
            gate,
            expected_tag_commit=self.TAG_COMMIT,
            expected_source_parent_commit=self.SOURCE_PARENT,
            expected_ci_workflow_sha256="c" * 64,
            expected_codeql_workflow_sha256="d" * 64,
        )
        self.assertIn("ABI2_SOURCE_SECURITY_GATE_PASS", stdout.getvalue())

    def test_release_checkout_binding_uses_fixed_git_and_exact_results_child(
        self,
    ) -> None:
        invocations: list[tuple[list[str], dict[str, object]]] = []

        def capture(arguments: list[str], **kwargs: object) -> mock.Mock:
            invocations.append((arguments, kwargs))
            command = " ".join(arguments)
            if "cat-file -t" in command:
                payload = b"tag\n"
            elif "rev-parse --verify" in command:
                payload = f"{self.TAG_COMMIT}\n".encode("ascii")
            elif "rev-list --parents" in command:
                payload = (
                    f"{self.TAG_COMMIT} {self.SOURCE_PARENT}\n".encode("ascii")
                )
            elif "diff --name-only" in command:
                payload = b"artifact/results.json\n"
            elif "status --porcelain=v1" in command:
                payload = b""
            elif "show -s --format=%ct" in command:
                payload = b"1786700000\n"
            else:
                self.fail(f"unexpected Git fixture command: {command}")
            return mock.Mock(returncode=0, stdout=payload)

        with mock.patch.object(candidate_attestation, "capture_stdout", capture):
            source_epoch = candidate_attestation.verify_candidate_checkout(
                self.TAG_COMMIT,
                expected_source_parent=self.SOURCE_PARENT,
                source_environment={},
            )

        self.assertEqual("1786700000", source_epoch)
        self.assertEqual(8, len(invocations))
        for arguments, kwargs in invocations:
            self.assertEqual(candidate_attestation.GIT, arguments[0])
            self.assertIn("core.fsmonitor=false", arguments)
            self.assertIn("core.hooksPath=/dev/null", arguments)
            self.assertEqual(
                candidate_attestation.github_release.git_observation_environment(),
                kwargs["environment"],
            )
        self.assertTrue(
            any("--untracked-files=all" in arguments for arguments, _ in invocations)
        )

    def test_release_checkout_binding_rejects_non_results_child(self) -> None:
        def capture(arguments: list[str], **_kwargs: object) -> mock.Mock:
            command = " ".join(arguments)
            if "cat-file -t" in command:
                payload = b"tag\n"
            elif "rev-parse --verify" in command:
                payload = f"{self.TAG_COMMIT}\n".encode("ascii")
            elif "rev-list --parents" in command:
                payload = f"{self.TAG_COMMIT} {'c' * 40}\n".encode("ascii")
            else:
                self.fail(f"unexpected Git fixture command: {command}")
            return mock.Mock(returncode=0, stdout=payload)

        with (
            mock.patch.object(candidate_attestation, "capture_stdout", capture),
            self.assertRaisesRegex(
                CandidateAttestationError,
                "not the direct results-only child",
            ),
        ):
            candidate_attestation.verify_candidate_checkout(
                self.TAG_COMMIT,
                expected_source_parent=self.SOURCE_PARENT,
                source_environment={},
            )

    def test_snapshot_uses_contract_order_and_exact_bytes(self) -> None:
        candidate = self._candidate("valid-candidate")

        snapshot = snapshot_candidate(candidate)

        self.assertEqual(
            list(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
            [item.name for item in snapshot.files],
        )
        for item in snapshot.files:
            payload = (candidate / item.name).read_bytes()
            self.assertEqual(len(payload), item.size)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), item.sha256)
        self.assertEqual(snapshot.subjects(), [item.subject() for item in snapshot.files])

    def test_snapshot_rejects_tamper_extra_symlink_and_noncanonical_sums(self) -> None:
        def tamper(candidate: pathlib.Path) -> None:
            (candidate / PLATFORM_CANDIDATE_ASSETS[0]).write_bytes(b"tampered\n")

        def extra(candidate: pathlib.Path) -> None:
            (candidate / "unexpected.bin").write_bytes(b"unexpected\n")

        def symlink(candidate: pathlib.Path) -> None:
            (candidate / "unsafe-link").symlink_to(
                candidate / PLATFORM_CANDIDATE_ASSETS[0]
            )

        def reorder(candidate: pathlib.Path) -> None:
            sums = candidate / CANDIDATE_SUMS
            lines = sums.read_text(encoding="ascii").splitlines(keepends=True)
            sums.write_text("".join(reversed(lines)), encoding="ascii")

        for name, mutation in (
            ("tamper", tamper),
            ("extra", extra),
            ("symlink", symlink),
            ("reorder", reorder),
        ):
            with self.subTest(name=name):
                candidate = self._candidate(f"candidate-{name}")
                mutation(candidate)
                with self.assertRaises(CandidateAttestationError):
                    snapshot_candidate(candidate)

    def test_snapshot_file_is_private_strict_and_exclusive(self) -> None:
        candidate = self._candidate("private-snapshot-candidate")
        snapshot_path, projection_path = self._private_output_paths("private-output")

        write_candidate_snapshot(candidate, snapshot_path, projection_path)

        metadata = snapshot_path.stat()
        self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
        self.assertEqual(1, metadata.st_nlink)
        self.assertEqual(
            snapshot_candidate(candidate).document(),
            load_candidate_snapshot(snapshot_path).document(),
        )
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(candidate, snapshot_path, projection_path)

    def test_shared_atomic_snapshot_and_projection_writers_recover_without_partials(
        self,
    ) -> None:
        candidate = self._candidate("atomic-writer-candidate")
        snapshot_path, projection_path = self._private_output_paths(
            "atomic-snapshot-output"
        )
        injected = candidate_attestation.PublicationReceiptIOError(
            "injected shared atomic failure"
        )

        with mock.patch.object(
            candidate_attestation,
            "write_private_json_noreplace_at",
            side_effect=injected,
        ):
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "injected shared atomic failure",
            ):
                write_candidate_snapshot(candidate, snapshot_path, projection_path)
        self.assertFalse(snapshot_path.exists())
        self.assertEqual(
            [],
            list(snapshot_path.parent.glob(f".{CANDIDATE_SNAPSHOT_NAME}.pending-*")),
        )

        write_candidate_snapshot(candidate, snapshot_path, projection_path)
        self.assertEqual(
            snapshot_candidate(candidate).document(),
            load_candidate_snapshot(snapshot_path).document(),
        )

        _, projection_path = self._private_output_paths("atomic-projection-output")
        projection = {"kind": "fixture", "schema_version": 1}
        with mock.patch.object(
            candidate_attestation,
            "write_private_json_noreplace_at",
            side_effect=injected,
        ):
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "injected shared atomic failure",
            ):
                candidate_attestation._write_private_json(
                    projection_path,
                    PROJECTION_NAME,
                    projection,
                    "candidate projection",
                )
        self.assertFalse(projection_path.exists())
        self.assertEqual(
            [],
            list(projection_path.parent.glob(f".{PROJECTION_NAME}.pending-*")),
        )

        digest = candidate_attestation._write_private_json(
            projection_path,
            PROJECTION_NAME,
            projection,
            "candidate projection",
        )
        payload = projection_path.read_bytes()
        self.assertEqual(projection, json.loads(payload))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)

    def test_projection_target_must_be_absolute_private_exact_and_absent(self) -> None:
        candidate = self._candidate("projection-policy-candidate")

        broad_parent = self.root / "broad-parent"
        broad_parent.mkdir(mode=0o755)
        os.chmod(broad_parent, 0o755)
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(
                candidate,
                broad_parent / CANDIDATE_SNAPSHOT_NAME,
                broad_parent / PROJECTION_NAME,
            )

        snapshot_path, projection_path = self._private_output_paths("exact-output")
        projection_path.write_bytes(b"must not be overwritten\n")
        os.chmod(projection_path, 0o600)
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(candidate, snapshot_path, projection_path)
        self.assertEqual(b"must not be overwritten\n", projection_path.read_bytes())
        self.assertFalse(snapshot_path.exists())

        relative_parent = pathlib.Path("relative-output")
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(
                candidate,
                relative_parent / CANDIDATE_SNAPSHOT_NAME,
                relative_parent / PROJECTION_NAME,
            )

        wrong_snapshot, _ = self._private_output_paths("wrong-leaf-output")
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(
                candidate,
                wrong_snapshot,
                wrong_snapshot.parent / "projection.json",
            )

    def test_projection_parent_must_be_disjoint_from_candidate_tree(self) -> None:
        candidate = self._candidate("disjoint-candidate")
        os.chmod(candidate, 0o700)
        snapshot_path, _ = self._private_output_paths("disjoint-snapshot")
        projection_in_root = candidate / PROJECTION_NAME

        with mock.patch.object(
            candidate_attestation,
            "CANDIDATE_PROJECTION_ROOT",
            self.candidate_root,
        ):
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "projection parent is inside the candidate directory",
            ):
                write_candidate_snapshot(
                    candidate,
                    snapshot_path,
                    projection_in_root,
                )
            self.assertFalse(snapshot_path.exists())
            self.assertFalse(projection_in_root.exists())

            with self.assertRaisesRegex(
                CandidateAttestationError,
                "projection parent is inside the candidate directory",
            ):
                candidate_attestation.verify_candidate_attestations(
                    candidate,
                    "a" * 40,
                    projection_in_root,
                    self.raw_root / "unread-raw-attestations",
                    self.raw_root / "unread-candidate-snapshot.json",
                )
            self.assertFalse(projection_in_root.exists())

        descendant = candidate / "private-projection-output"
        descendant.mkdir(mode=0o700)
        os.chmod(descendant, 0o700)
        projection_in_descendant = descendant / PROJECTION_NAME
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(candidate, snapshot_path, projection_in_descendant)
        self.assertFalse(snapshot_path.exists())
        self.assertFalse(projection_in_descendant.exists())

    def test_fixed_roots_reject_prefix_traversal_tmp_and_symlink_escape(self) -> None:
        candidate = self._candidate("safe-candidate")
        _snapshot_path, projection = self._private_output_paths("safe-output")
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)

        evil_prefix = self.root / "abi2-platform-candidate-inputs-evil"
        evil_prefix.mkdir()
        tmp_candidate = pathlib.Path("/tmp/qperiapt-unsafe-candidate")
        traversal_candidate = self.candidate_root / "child" / ".." / ".." / "outside"
        symlink_candidate = self.candidate_root / "candidate-link"
        symlink_candidate.symlink_to(outside, target_is_directory=True)

        for unsafe in (
            tmp_candidate,
            evil_prefix,
            traversal_candidate,
            symlink_candidate,
        ):
            with self.subTest(candidate=unsafe):
                with self.assertRaises(CandidateAttestationError):
                    candidate_attestation.preflight_candidate_paths(
                        unsafe,
                        projection,
                    )
                self.assertFalse(projection.exists())

        symlink_parent = self.projection_root / "projection-link"
        symlink_parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(CandidateAttestationError):
            candidate_attestation.preflight_candidate_paths(
                candidate,
                symlink_parent / PROJECTION_NAME,
            )
        self.assertFalse((outside / PROJECTION_NAME).exists())

        os.chmod(self.candidate_root, 0o755)
        try:
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "safe root is not an owned non-symlink directory",
            ):
                candidate_attestation.preflight_candidate_paths(
                    candidate,
                    projection,
                )
        finally:
            os.chmod(self.candidate_root, 0o700)

    def test_private_snapshot_rejects_mode_and_hardlink_changes(self) -> None:
        candidate = self._candidate("metadata-candidate")
        snapshot_path, projection_path = self._private_output_paths("metadata-output")
        write_candidate_snapshot(candidate, snapshot_path, projection_path)

        os.chmod(snapshot_path, 0o644)
        with self.assertRaises(CandidateAttestationError):
            load_candidate_snapshot(snapshot_path)

        os.chmod(snapshot_path, 0o600)
        os.link(snapshot_path, snapshot_path.parent / "snapshot-hardlink.json")
        with self.assertRaises(CandidateAttestationError):
            load_candidate_snapshot(snapshot_path)


if __name__ == "__main__":
    unittest.main()
