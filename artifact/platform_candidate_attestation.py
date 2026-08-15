#!/usr/bin/env python3
"""Verify one fixed stable platform-candidate provenance transaction.

This module owns fixed-system Git observations, pinned GitHub CLI execution,
candidate byte snapshots, strict verification-result parsing, the pre/post
comparison, and one PII-safe projection.  Shell entrypoints only sequence these
typed, fail-closed boundaries.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from collections.abc import Callable, Iterator, Mapping
from typing import Any, NoReturn, Sequence

from bounded_process import BoundedProcessError, capture_stdout
import github_release_observation as github_release
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    FileSnapshot,
    consume_regular_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from publication_receipt_io import (
    PublicationReceiptCommittedError,
    PublicationReceiptIOError,
    write_private_bytes_noreplace_at,
    write_private_json_noreplace_at,
)
from git_provenance import GIT
from platform_distribution_contract import (
    CI_WORKFLOW_NAME,
    CI_WORKFLOW_PATH,
    CODEQL_JOB_CONTRACT,
    CODEQL_WORKFLOW_NAME,
    CODEQL_WORKFLOW_PATH,
    CONSTANT_TIME_JOB_CONTRACT,
    MAX_WORKFLOW_RUN_ATTEMPT,
    MAX_WORKFLOW_RUN_ID,
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    PlatformDistributionContractError,
    RELEASE_TAG,
    REPOSITORY as CONTRACT_REPOSITORY,
    SOURCE_SECURITY_GATE,
    SOURCE_SECURITY_GATE_KIND,
    SOURCE_SECURITY_GATE_SCHEMA_VERSION,
    validate_source_security_gate,
)


MAX_ATTESTATION_BYTES = 16 * 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_CHECKSUM_BYTES = 1024 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_SECURITY_GATE_BYTES = 1024 * 1024
MAX_GITHUB_API_BYTES = 16 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 1024 * 1024
MAX_WORKFLOW_TOOL_BYTES = 512 * 1024 * 1024
MAX_RUN_ID = MAX_WORKFLOW_RUN_ID
MAX_RUN_ATTEMPT = MAX_WORKFLOW_RUN_ATTEMPT
REPOSITORY = "billlza/q-periapt"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
REPOSITORY_OWNER_URL = "https://github.com/billlza"
WORKFLOW_PATH = ".github/workflows/abi2-platform-candidate.yml"
RELEASE_REF = f"refs/tags/{RELEASE_TAG}"
WORKFLOW_URI = f"{REPOSITORY_URL}/{WORKFLOW_PATH}@{RELEASE_REF}"
RUN_URI_PREFIX = f"{REPOSITORY_URL}/actions/runs/"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VERIFICATION_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
)
CANDIDATE_SNAPSHOT_NAME = "candidate-snapshot.json"
PROJECTION_NAME = "candidate-attestation-projection.json"
REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
CANDIDATE_INPUT_ROOT = REPOSITORY_ROOT / "target" / "abi2-platform-candidate-inputs"
CANDIDATE_VERIFICATION_ROOT = (
    REPOSITORY_ROOT
    / "target"
    / "abi2-platform-candidate-verification"
)
CANDIDATE_RAW_ROOT = CANDIDATE_VERIFICATION_ROOT / "raw"
CANDIDATE_PROJECTION_ROOT = (
    REPOSITORY_ROOT / "target" / "abi2-platform-candidate-projections"
)
WORKFLOW_CANDIDATE_ROOT = REPOSITORY_ROOT / "candidate"
WORKFLOW_GITHUB_CLI = pathlib.Path("/usr/bin/gh")
RESULTS_PATH = REPOSITORY_ROOT / "artifact" / "results.json"
SNAPSHOT_SCHEMA_VERSION = 2
SNAPSHOT_KIND = "qperiapt.platform_candidate_snapshot"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_SUBJECT_NAME = re.compile(r"^[A-Za-z0-9._+-]+$")
SAFE_DIRECTORY_LEAF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
STRICT_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


class CandidateAttestationError(ValueError):
    """Candidate bytes or one verification result violates release policy."""


@dataclass(frozen=True, slots=True)
class CandidateFile:
    """One exact candidate subject sampled from a regular file."""

    name: str
    size: int
    sha256: str

    def record(self) -> dict[str, object]:
        """Return the PII-safe snapshot record."""

        return {"bytes": self.size, "name": self.name, "sha256": self.sha256}

    def subject(self) -> dict[str, object]:
        """Return the in-toto subject projection."""

        return {"digest": {"sha256": self.sha256}, "name": self.name}


@dataclass(frozen=True, slots=True)
class WorkflowToolIdentity:
    """One immutable hosted-workflow tool sample used during API observation."""

    path: str
    device: int
    inode: int
    mode: int
    uid: int
    link_count: int
    size: int
    sha256: str

@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """The exact six-file CI candidate sampled at one point in time."""

    files: tuple[CandidateFile, ...]

    def document(self) -> dict[str, object]:
        """Return the canonical private snapshot document."""

        return {
            "files": [item.record() for item in self.files],
            "kind": SNAPSHOT_KIND,
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
        }

    def subjects(self) -> list[dict[str, object]]:
        """Return subjects in the workflow's fixed attestation order."""

        return [item.subject() for item in self.files]


@dataclass(frozen=True, slots=True)
class VerifiedRecord:
    """Canonicalized policy fields from one exact verification result."""

    statement: bytes
    record: bytes
    run_id: int
    run_attempt: int
    verified_at: str


def _fail(message: str) -> NoReturn:
    raise CandidateAttestationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        f"{label} must be an object",
    )
    return value


def _exact_keys(
    value: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    _require(frozenset(value) == expected, f"{label} fields differ")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CandidateAttestationError(
            "verification result is not canonical JSON"
        ) from exc


def _private_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise EvidenceIOError("private evidence file metadata differs")


def _snapshot_file(
    path: pathlib.Path,
    *,
    maximum: int,
    label: str,
    private: bool = False,
) -> FileSnapshot:
    try:
        return read_regular_snapshot(
            path,
            maximum=maximum,
            label=label,
            validate_metadata=_private_file_metadata if private else None,
        )
    except EvidenceIOError as exc:
        raise CandidateAttestationError(f"cannot safely read {label}") from exc


def _results_manifest() -> dict[str, Any]:
    snapshot = _snapshot_file(
        RESULTS_PATH,
        maximum=16 * 1024 * 1024,
        label="tagged results manifest",
    )
    try:
        value = parse_strict_json_bytes(snapshot.data, label="tagged results manifest")
    except EvidenceIOError as exc:
        raise CandidateAttestationError("tagged results manifest is invalid") from exc
    manifest = _object(value, "tagged results manifest")
    return manifest


def _source_parent_from_results() -> str:
    manifest = _results_manifest()
    provenance = _object(manifest.get("provenance"), "tagged results provenance")
    source_parent = provenance.get("snapshot_commit")
    _require(
        isinstance(source_parent, str) and HEX_40.fullmatch(source_parent) is not None,
        "tagged results source parent is malformed",
    )
    return source_parent


def validate_tag_source_currentness(expected_source_parent: str) -> None:
    """Apply the central stable-source authority to the tagged results bytes."""

    _require(
        HEX_40.fullmatch(expected_source_parent) is not None,
        "expected source parent is malformed",
    )
    manifest = _results_manifest()
    provenance = _object(manifest.get("provenance"), "tagged results provenance")
    _require(
        provenance.get("snapshot_commit") == expected_source_parent,
        "tagged stable-source authority differs from S",
    )
    try:
        import release_publication_contract

        release_publication_contract.validate_stable_source_currentness(manifest)
    except release_publication_contract.ReleasePublicationContractError as exc:
        raise CandidateAttestationError(str(exc)) from exc


def _workflow_sha256(relative: str, *, label: str) -> str:
    snapshot = _snapshot_file(
        REPOSITORY_ROOT / relative,
        maximum=4 * 1024 * 1024,
        label=label,
    )
    return snapshot.sha256


def _api_positive_integer(value: object, *, maximum: int, label: str) -> int:
    _require(
        type(value) is int and 0 < value <= maximum,
        f"{label} must be a bounded positive integer",
    )
    return value


def _api_collection(
    value: object, *, items_key: str, label: str
) -> list[dict[str, Any]]:
    collection = _object(value, label)
    _exact_keys(collection, frozenset({"total_count", items_key}), label)
    items = collection[items_key]
    _require(isinstance(items, list), f"{label} items must be a list")
    _require(
        type(collection["total_count"]) is int
        and collection["total_count"] == len(items),
        f"{label} is incomplete or has an invalid count",
    )
    parsed = [_object(item, f"{label} item") for item in items]
    return parsed


def _workflow_github_cli_identity() -> WorkflowToolIdentity:
    path = WORKFLOW_GITHUB_CLI
    _require(path.is_absolute(), "workflow GitHub CLI path is not absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateAttestationError(
            "cannot resolve the workflow GitHub CLI"
        ) from exc
    _require(
        resolved == path,
        "workflow GitHub CLI path must be canonical and not a symlink",
    )
    observed: os.stat_result | None = None

    def validate_metadata(metadata: os.stat_result) -> None:
        nonlocal observed
        mode = stat.S_IMODE(metadata.st_mode)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_nlink == 1
            and mode & 0o111 != 0
            and mode & 0o022 == 0,
            "workflow GitHub CLI metadata is unsafe",
        )
        observed = metadata

    try:
        snapshot: FileDigestSnapshot = consume_regular_snapshot(
            path,
            maximum=MAX_WORKFLOW_TOOL_BYTES,
            label="workflow GitHub CLI",
            validate_metadata=validate_metadata,
        )
    except EvidenceIOError as exc:
        raise CandidateAttestationError(
            "cannot safely snapshot the workflow GitHub CLI"
        ) from exc
    _require(snapshot.size > 0 and observed is not None, "workflow GitHub CLI is empty")
    assert observed is not None
    return WorkflowToolIdentity(
        path=str(path),
        device=observed.st_dev,
        inode=observed.st_ino,
        mode=observed.st_mode,
        uid=observed.st_uid,
        link_count=observed.st_nlink,
        size=snapshot.size,
        sha256=snapshot.sha256,
    )


def _workflow_github_environment(source: Mapping[str, str]) -> dict[str, str]:
    forbidden = sorted(
        name
        for name in source
        if name.startswith("GIT_")
        or (name.startswith("GH_") and name != "GH_TOKEN")
        or name in github_release.DANGEROUS_GITHUB_ENVIRONMENT
    )
    _require(not forbidden, "workflow GitHub environment contains trust overrides")
    _require(
        isinstance(source.get("GH_TOKEN"), str)
        and 0 < len(source["GH_TOKEN"]) <= 4_096
        and "\x00" not in source["GH_TOKEN"]
        and not source.get("GITHUB_TOKEN"),
        "workflow GitHub environment requires exactly GH_TOKEN",
    )
    return {
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PAGER": "cat",
        "GH_PROMPT_DISABLED": "1",
        "GH_TELEMETRY": "0",
        "GH_TOKEN": source["GH_TOKEN"],
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
        "TERM": "dumb",
    }


@contextlib.contextmanager
def _isolated_workflow_github_environment(
    environment: Mapping[str, str],
) -> Iterator[dict[str, str]]:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        temporary = tempfile.TemporaryDirectory(
            prefix="qperiapt-workflow-gh-",
            dir="/tmp",
        )
        directory = pathlib.Path(temporary.name)
        os.chmod(directory, 0o700)
        before = directory.lstat()
        _require(
            stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.geteuid()
            and stat.S_IMODE(before.st_mode) == 0o700
            and not any(directory.iterdir()),
            "workflow GitHub configuration directory is unsafe",
        )
        yield {
            **environment,
            "GH_CONFIG_DIR": str(directory),
            "HOME": str(directory),
        }
        after = directory.lstat()
        _require(
            (after.st_dev, after.st_ino, after.st_mode, after.st_uid)
            == (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
            and not any(directory.iterdir()),
            "workflow GitHub configuration changed during observation",
        )
    except OSError as exc:
        raise CandidateAttestationError(
            "cannot isolate the workflow GitHub configuration"
        ) from exc
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError as exc:
                raise CandidateAttestationError(
                    "cannot remove the workflow GitHub configuration"
                ) from exc


def _capture_workflow_github_cli(
    tool: WorkflowToolIdentity,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    maximum_bytes: int,
    label: str,
) -> bytes:
    _require(
        isinstance(tool, WorkflowToolIdentity)
        and bool(arguments)
        and all(
            isinstance(argument, str) and argument and "\x00" not in argument
            for argument in arguments
        ),
        "workflow GitHub command is malformed",
    )
    _require(
        _workflow_github_cli_identity() == tool,
        "workflow GitHub CLI changed before observation",
    )
    try:
        with _isolated_workflow_github_environment(environment) as isolated:
            result = capture_stdout(
                [tool.path, *arguments],
                timeout_seconds=120,
                maximum_bytes=maximum_bytes,
                stderr=subprocess.DEVNULL,
                environment=isolated,
            )
    except BoundedProcessError as exc:
        raise CandidateAttestationError(f"{label} failed safely") from exc
    finally:
        _require(
            _workflow_github_cli_identity() == tool,
            "workflow GitHub CLI changed during observation",
        )
    _require(result.returncode == 0 and result.stdout, f"{label} was rejected")
    return result.stdout


def _select_latest_exact_run(
    value: object,
    *,
    expected_commit: str,
    workflow_name: str,
    workflow_path: str,
    label: str,
) -> dict[str, Any]:
    runs = _api_collection(value, items_key="workflow_runs", label=label)
    ids: set[int] = set()
    candidates: list[dict[str, Any]] = []
    for run in runs:
        run_id = _api_positive_integer(
            run.get("id"), maximum=MAX_RUN_ID, label=f"{label} run id"
        )
        _require(run_id not in ids, f"{label} contains duplicate run ids")
        ids.add(run_id)
        if (
            run.get("name") == workflow_name
            and run.get("path") == workflow_path
            and run.get("head_sha") == expected_commit
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
        ):
            _api_positive_integer(
                run.get("run_attempt"),
                maximum=MAX_RUN_ATTEMPT,
                label=f"{label} run attempt",
            )
            candidates.append(run)
    _require(candidates, f"{label} has no exact run at R")
    selected = max(candidates, key=lambda run: run["id"])
    _require(
        selected.get("status") == "completed"
        and selected.get("conclusion") == "success",
        f"{label} latest exact run at R did not complete successfully",
    )
    return selected


def _job_record(
    raw: dict[str, Any],
    *,
    run_id: int,
    run_attempt: int,
    label: str,
) -> tuple[int, str]:
    job_id = _api_positive_integer(
        raw.get("id"), maximum=MAX_RUN_ID, label=f"{label} id"
    )
    _require(raw.get("run_id") == run_id, f"{label} run id differs")
    _require(raw.get("run_attempt") == run_attempt, f"{label} run attempt differs")
    name = raw.get("name")
    _require(isinstance(name, str), f"{label} name is malformed")
    return job_id, name


def _selected_job_map(
    value: object,
    *,
    run_id: int,
    run_attempt: int,
    required_names: frozenset[str],
    exact_names: bool,
    label: str,
) -> dict[str, int]:
    jobs = _api_collection(value, items_key="jobs", label=label)
    by_name: dict[str, int] = {}
    ids: set[int] = set()
    all_names: set[str] = set()
    for raw in jobs:
        job_id, name = _job_record(
            raw,
            run_id=run_id,
            run_attempt=run_attempt,
            label=f"{label} job",
        )
        _require(job_id not in ids, f"{label} job ids are not unique")
        _require(name not in all_names, f"{label} job names are not unique")
        ids.add(job_id)
        all_names.add(name)
        if name in required_names:
            _require(
                raw.get("status") == "completed"
                and raw.get("conclusion") == "success",
                f"{label} required job did not complete successfully: {name}",
            )
            by_name[name] = job_id
        elif exact_names:
            _fail(f"{label} contains an unexpected job: {name}")
    _require(set(by_name) == set(required_names), f"{label} required job set differs")
    return by_name


def _selected_source_security_observations(
    ci_runs: object,
    ci_jobs: object,
    codeql_runs: object,
    codeql_jobs: object,
    *,
    expected_commit: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, int], dict[str, int]]:
    """Validate and select the exact latest runs, attempts, and required jobs."""

    ci_run = _select_latest_exact_run(
        ci_runs,
        expected_commit=expected_commit,
        workflow_name=CI_WORKFLOW_NAME,
        workflow_path=CI_WORKFLOW_PATH,
        label="CI workflow runs",
    )
    codeql_run = _select_latest_exact_run(
        codeql_runs,
        expected_commit=expected_commit,
        workflow_name=CODEQL_WORKFLOW_NAME,
        workflow_path=CODEQL_WORKFLOW_PATH,
        label="CodeQL workflow runs",
    )
    ci_by_name = _selected_job_map(
        ci_jobs,
        run_id=ci_run["id"],
        run_attempt=ci_run["run_attempt"],
        required_names=frozenset(
            name for _arch, _implementation, name in CONSTANT_TIME_JOB_CONTRACT
        ),
        exact_names=False,
        label="CI workflow jobs",
    )
    codeql_by_name = _selected_job_map(
        codeql_jobs,
        run_id=codeql_run["id"],
        run_attempt=codeql_run["run_attempt"],
        required_names=frozenset(name for _language, name in CODEQL_JOB_CONTRACT),
        exact_names=True,
        label="CodeQL workflow jobs",
    )
    return ci_run, codeql_run, ci_by_name, codeql_by_name


def _query_source_security_api(
    api: Callable[[str, str], object],
    *,
    expected_commit: str,
) -> tuple[
    object,
    object,
    object,
    object,
    dict[str, Any],
    dict[str, Any],
]:
    """Query and validate one complete exact-R CI/CodeQL observation set."""

    ci_runs = api(
        f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs?"
        f"head_sha={expected_commit}&branch=main&event=push&per_page=100",
        "CI workflow runs API response",
    )
    codeql_runs = api(
        f"repos/{REPOSITORY}/actions/workflows/codeql.yml/runs?"
        f"head_sha={expected_commit}&branch=main&event=push&per_page=100",
        "CodeQL workflow runs API response",
    )
    ci_run = _select_latest_exact_run(
        ci_runs,
        expected_commit=expected_commit,
        workflow_name=CI_WORKFLOW_NAME,
        workflow_path=CI_WORKFLOW_PATH,
        label="CI workflow runs",
    )
    codeql_run = _select_latest_exact_run(
        codeql_runs,
        expected_commit=expected_commit,
        workflow_name=CODEQL_WORKFLOW_NAME,
        workflow_path=CODEQL_WORKFLOW_PATH,
        label="CodeQL workflow runs",
    )
    ci_jobs = api(
        f"repos/{REPOSITORY}/actions/runs/{ci_run['id']}/attempts/"
        f"{ci_run['run_attempt']}/jobs?filter=all&per_page=100",
        "CI workflow jobs API response",
    )
    codeql_jobs = api(
        f"repos/{REPOSITORY}/actions/runs/{codeql_run['id']}/attempts/"
        f"{codeql_run['run_attempt']}/jobs?filter=all&per_page=100",
        "CodeQL workflow jobs API response",
    )
    selected_ci, selected_codeql, _ci_jobs, _codeql_jobs = (
        _selected_source_security_observations(
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            expected_commit=expected_commit,
        )
    )
    return (
        ci_runs,
        ci_jobs,
        codeql_runs,
        codeql_jobs,
        selected_ci,
        selected_codeql,
    )


def _github_api_arguments(endpoint: str) -> list[str]:
    """Bind every source-security observation to one explicit REST contract."""

    return [
        "api",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {github_release.GITHUB_API_VERSION}",
        endpoint,
    ]


def build_source_security_gate(
    ci_runs: object,
    ci_jobs: object,
    codeql_runs: object,
    codeql_jobs: object,
    *,
    expected_tag_commit: str,
    expected_source_parent_commit: str,
    ci_workflow_sha256: str,
    codeql_workflow_sha256: str,
    github_cli_sha256: str,
    github_cli_version: str,
) -> dict[str, object]:
    """Select the highest exact-R runs and project only bounded public fields."""

    _require(CONTRACT_REPOSITORY == REPOSITORY, "repository contracts differ")
    _require(
        HEX_40.fullmatch(expected_tag_commit) is not None,
        "security gate tag commit is malformed",
    )
    _require(
        HEX_40.fullmatch(expected_source_parent_commit) is not None,
        "security gate source parent is malformed",
    )
    ci_run, codeql_run, ci_by_name, codeql_by_name = (
        _selected_source_security_observations(
            ci_runs,
            ci_jobs,
            codeql_runs,
            codeql_jobs,
            expected_commit=expected_tag_commit,
        )
    )
    ci_run_id = ci_run["id"]
    ci_attempt = ci_run["run_attempt"]
    codeql_run_id = codeql_run["id"]
    codeql_attempt = codeql_run["run_attempt"]
    constant_time_jobs = []
    for architecture, implementation, name in CONSTANT_TIME_JOB_CONTRACT:
        _require(name in ci_by_name, f"required constant-time job is absent: {name}")
        constant_time_jobs.append(
            {
                "architecture": architecture,
                "conclusion": "success",
                "implementation": implementation,
                "job_id": ci_by_name[name],
                "name": name,
                "status": "completed",
            }
        )
    codeql_job_records = [
        {
            "conclusion": "success",
            "job_id": codeql_by_name[name],
            "language": language,
            "name": name,
            "status": "completed",
        }
        for language, name in CODEQL_JOB_CONTRACT
    ]

    def workflow_record(
        run: dict[str, Any],
        *,
        workflow_name: str,
        workflow_path: str,
        workflow_sha256: str,
        jobs: list[dict[str, object]],
    ) -> dict[str, object]:
        return {
            "conclusion": "success",
            "event": "push",
            "head_branch": "main",
            "head_sha": expected_tag_commit,
            "jobs": jobs,
            "run_attempt": run["run_attempt"],
            "run_id": run["id"],
            "status": "completed",
            "workflow_name": workflow_name,
            "workflow_path": workflow_path,
            "workflow_sha256": workflow_sha256,
        }

    gate: dict[str, object] = {
        "kind": SOURCE_SECURITY_GATE_KIND,
        "observation_tools": {
            "github_cli": {
                "name": "gh",
                "path": "/usr/bin/gh",
                "sha256": github_cli_sha256,
                "version": github_cli_version,
            },
        },
        "repository": REPOSITORY,
        "schema_version": SOURCE_SECURITY_GATE_SCHEMA_VERSION,
        "source_parent_commit": expected_source_parent_commit,
        "tag_commit": expected_tag_commit,
        "workflows": {
            "ci": workflow_record(
                ci_run,
                workflow_name=CI_WORKFLOW_NAME,
                workflow_path=CI_WORKFLOW_PATH,
                workflow_sha256=ci_workflow_sha256,
                jobs=constant_time_jobs,
            ),
            "codeql": workflow_record(
                codeql_run,
                workflow_name=CODEQL_WORKFLOW_NAME,
                workflow_path=CODEQL_WORKFLOW_PATH,
                workflow_sha256=codeql_workflow_sha256,
                jobs=codeql_job_records,
            ),
        },
    }
    try:
        validate_source_security_gate(
            gate,
            expected_tag_commit=expected_tag_commit,
            expected_source_parent_commit=expected_source_parent_commit,
            expected_ci_workflow_sha256=ci_workflow_sha256,
            expected_codeql_workflow_sha256=codeql_workflow_sha256,
        )
    except PlatformDistributionContractError as exc:
        raise CandidateAttestationError(str(exc)) from exc
    return gate


def _load_api_json(path: pathlib.Path, *, label: str) -> object:
    _require(path.is_absolute(), f"{label} path must be absolute")
    snapshot = _snapshot_file(path, maximum=MAX_GITHUB_API_BYTES, label=label)
    try:
        return parse_strict_json_bytes(snapshot.data, label=label)
    except EvidenceIOError as exc:
        raise CandidateAttestationError(f"{label} JSON is invalid") from exc


def _write_public_gate_noreplace(path: pathlib.Path, value: object) -> str:
    _require(path.is_absolute(), "source security gate output must be absolute")
    _require(path.name == SOURCE_SECURITY_GATE, "source security gate output leaf differs")
    root_text = os.path.realpath(os.fspath(WORKFLOW_CANDIDATE_ROOT))
    supplied_parent = os.path.abspath(os.fspath(path.parent))
    _require(root_text == supplied_parent, "source security gate output parent differs")
    try:
        metadata = path.parent.lstat()
    except OSError as exc:
        raise CandidateAttestationError("cannot inspect source security gate parent") from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and not path.parent.is_symlink()
        and metadata.st_uid == os.geteuid(),
        "source security gate parent is not an owned non-symlink directory",
    )
    _require(
        stat.S_IMODE(metadata.st_mode) == 0o700,
        "source security gate parent must have mode 0700",
    )
    try:
        payload = (
            json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CandidateAttestationError("source security gate is not JSON") from exc
    _require(
        0 < len(payload) <= MAX_SECURITY_GATE_BYTES,
        "source security gate size is outside bounds",
    )
    with _private_directory_handle(
        path.parent,
        "source security gate parent",
    ) as directory_fd:
        try:
            return write_private_bytes_noreplace_at(
                directory_fd,
                SOURCE_SECURITY_GATE,
                payload,
                label="source security gate",
                maximum=MAX_SECURITY_GATE_BYTES,
            )
        except PublicationReceiptCommittedError:
            raise
        except PublicationReceiptIOError as exc:
            raise CandidateAttestationError(str(exc)) from exc


def assemble_source_security_gate(
    ci_runs_path: pathlib.Path,
    ci_jobs_path: pathlib.Path,
    codeql_runs_path: pathlib.Path,
    codeql_jobs_path: pathlib.Path,
    expected_tag_commit: str,
    expected_source_parent_commit: str,
    output_path: pathlib.Path,
    github_cli_sha256: str,
    github_cli_version: str,
) -> str:
    """Create the fixed attested security-gate subject from bounded API snapshots."""

    _require(
        _source_parent_from_results() == expected_source_parent_commit,
        "source security gate S differs from tagged results",
    )
    ci_sha256 = _workflow_sha256(CI_WORKFLOW_PATH, label="CI workflow source")
    codeql_sha256 = _workflow_sha256(
        CODEQL_WORKFLOW_PATH, label="CodeQL workflow source"
    )
    gate = build_source_security_gate(
        _load_api_json(ci_runs_path, label="CI workflow runs API response"),
        _load_api_json(ci_jobs_path, label="CI workflow jobs API response"),
        _load_api_json(codeql_runs_path, label="CodeQL workflow runs API response"),
        _load_api_json(codeql_jobs_path, label="CodeQL workflow jobs API response"),
        expected_tag_commit=expected_tag_commit,
        expected_source_parent_commit=expected_source_parent_commit,
        ci_workflow_sha256=ci_sha256,
        codeql_workflow_sha256=codeql_sha256,
        github_cli_sha256=github_cli_sha256,
        github_cli_version=github_cli_version,
    )
    return _write_public_gate_noreplace(output_path, gate)


def assemble_live_source_security_gate(
    expected_tag_commit: str,
    expected_source_parent_commit: str,
    output_path: pathlib.Path,
    *,
    source_environment: Mapping[str, str] | None = None,
) -> str:
    """Query exact-R hosted runs with one resampled workflow-owned CLI."""

    _require(
        _source_parent_from_results() == expected_source_parent_commit,
        "source security gate S differs from tagged results",
    )
    environment = _workflow_github_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = _workflow_github_cli_identity()
    version_bytes = _capture_workflow_github_cli(
        tool,
        ["version"],
        environment=environment,
        maximum_bytes=4 * 1024,
        label="workflow GitHub CLI version",
    )
    try:
        version_lines = version_bytes.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise CandidateAttestationError(
            "workflow GitHub CLI version is not ASCII"
        ) from exc
    _require(version_lines, "workflow GitHub CLI version is empty")
    github_cli_version = version_lines[0]

    def api(endpoint: str, label: str) -> object:
        raw = _capture_workflow_github_cli(
            tool,
            _github_api_arguments(endpoint),
            environment=environment,
            maximum_bytes=MAX_GITHUB_API_BYTES,
            label=label,
        )
        try:
            return parse_strict_json_bytes(raw, label=label)
        except EvidenceIOError as exc:
            raise CandidateAttestationError(f"{label} JSON is invalid") from exc

    ci_runs, ci_jobs, codeql_runs, codeql_jobs, _ci_run, _codeql_run = (
        _query_source_security_api(api, expected_commit=expected_tag_commit)
    )
    gate = build_source_security_gate(
        ci_runs,
        ci_jobs,
        codeql_runs,
        codeql_jobs,
        expected_tag_commit=expected_tag_commit,
        expected_source_parent_commit=expected_source_parent_commit,
        ci_workflow_sha256=_workflow_sha256(
            CI_WORKFLOW_PATH,
            label="CI workflow source",
        ),
        codeql_workflow_sha256=_workflow_sha256(
            CODEQL_WORKFLOW_PATH,
            label="CodeQL workflow source",
        ),
        github_cli_sha256=tool.sha256,
        github_cli_version=github_cli_version,
    )
    return _write_public_gate_noreplace(output_path, gate)


def verify_pretag_security_readiness(
    expected_tag_commit: str,
    expected_source_parent_commit: str,
    *,
    source_environment: Mapping[str, str] | None = None,
) -> tuple[int, int, int, int, str]:
    """Double-sample the exact-R CI/CodeQL authority before immutable tags exist."""

    _require(
        HEX_40.fullmatch(expected_tag_commit) is not None,
        "pre-tag security R is malformed",
    )
    _require(
        HEX_40.fullmatch(expected_source_parent_commit) is not None,
        "pre-tag security S is malformed",
    )
    _require(
        _source_parent_from_results() == expected_source_parent_commit,
        "pre-tag security S differs from results",
    )
    validate_tag_source_currentness(expected_source_parent_commit)
    try:
        environment = github_release.github_cli_environment(
            os.environ if source_environment is None else source_environment
        )
        tool = github_release.select_github_cli()

        def api(endpoint: str, label: str) -> object:
            raw = github_release.capture_github_cli(
                tool,
                _github_api_arguments(endpoint),
                timeout_seconds=120,
                maximum_bytes=MAX_GITHUB_API_BYTES,
                environment=environment,
                label=label,
            )
            try:
                return parse_strict_json_bytes(raw, label=label)
            except EvidenceIOError as exc:
                raise CandidateAttestationError(f"{label} JSON is invalid") from exc

        before = _query_source_security_api(
            api,
            expected_commit=expected_tag_commit,
        )
        after = _query_source_security_api(
            api,
            expected_commit=expected_tag_commit,
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise CandidateAttestationError(str(exc)) from exc
    _require(
        before[:4] == after[:4]
        and before[4]["id"] == after[4]["id"]
        and before[4]["run_attempt"] == after[4]["run_attempt"]
        and before[5]["id"] == after[5]["id"]
        and before[5]["run_attempt"] == after[5]["run_attempt"],
        "pre-tag security observations changed between samples",
    )
    ci_run = before[4]
    codeql_run = before[5]
    return (
        ci_run["id"],
        ci_run["run_attempt"],
        codeql_run["id"],
        codeql_run["run_attempt"],
        tool.sha256,
    )


def _validate_contract_names() -> None:
    expected = (
        *PLATFORM_CANDIDATE_ASSETS,
        "CANDIDATE_SHA256SUMS",
        SOURCE_SECURITY_GATE,
    )
    _require(
        PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS == expected,
        "candidate subject contract order differs",
    )
    _require(
        len(expected) == 6
        and len(set(expected)) == 6
        and all(SAFE_SUBJECT_NAME.fullmatch(name) is not None for name in expected),
        "candidate subject names are not six exact shell-safe leaves",
    )


def _normalized_safe_root(
    safe_root: pathlib.Path,
    *,
    label: str,
    required_mode: int | None = None,
) -> pathlib.Path:
    """Return one fixed, owned, canonical directory used as an I/O boundary."""

    root_text = os.path.realpath(os.fspath(safe_root))
    _require(
        safe_root.is_absolute()
        and root_text == os.path.abspath(os.fspath(safe_root)),
        f"{label} safe root must be canonical",
    )
    root = pathlib.Path(root_text)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise CandidateAttestationError(f"cannot inspect {label} safe root") from exc
    valid = (
        stat.S_ISDIR(metadata.st_mode)
        and not root.is_symlink()
        and metadata.st_uid == os.geteuid()
    )
    if required_mode is not None:
        valid = valid and stat.S_IMODE(metadata.st_mode) == required_mode
    _require(valid, f"{label} safe root is not an owned non-symlink directory")
    return root


def _normalize_path_under_root(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    label: str,
    required_root_mode: int | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Resolve a CLI path once and prove containment below one fixed root."""

    if not path.is_absolute():
        raise CandidateAttestationError(f"{label} must be absolute")
    root = _normalized_safe_root(
        safe_root,
        label=label,
        required_mode=required_root_mode,
    )
    supplied_text = os.fspath(path)
    normalized_text = os.path.realpath(supplied_text)
    root_text = os.fspath(root)
    if not normalized_text.startswith(root_text + os.sep):
        raise CandidateAttestationError(
            f"{label} is outside its fixed safe root"
        )
    if normalized_text != os.path.abspath(supplied_text):
        raise CandidateAttestationError(
            f"{label} must contain no symlink or traversal aliases"
        )
    return pathlib.Path(normalized_text), root


def _candidate_directory(path: pathlib.Path) -> pathlib.Path:
    normalized, _root = _normalize_path_under_root(
        path,
        safe_root=CANDIDATE_INPUT_ROOT,
        label="candidate directory",
        required_root_mode=0o700,
    )
    try:
        metadata = normalized.lstat()
    except OSError as exc:
        raise CandidateAttestationError("cannot inspect candidate directory") from exc
    _require(
        stat.S_ISDIR(metadata.st_mode) and not normalized.is_symlink(),
        "candidate directory must be a non-symlink directory",
    )
    return normalized


def _snapshot_candidate_root(root: pathlib.Path) -> CandidateSnapshot:
    """Sample an already-normalized candidate directory."""

    _validate_contract_names()
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise CandidateAttestationError("cannot enumerate candidate directory") from exc
    actual: set[str] = set()
    for entry_path in entries:
        try:
            metadata = entry_path.lstat()
        except OSError as exc:
            raise CandidateAttestationError("cannot inspect candidate entry") from exc
        _require(
            stat.S_ISREG(metadata.st_mode) and not entry_path.is_symlink(),
            "candidate directory contains a non-regular entry",
        )
        actual.add(entry_path.name)
    expected = set(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS)
    _require(actual == expected, "candidate asset set differs")

    sums_name = "CANDIDATE_SHA256SUMS"
    sums_snapshot = _snapshot_file(
        root / sums_name,
        maximum=MAX_CHECKSUM_BYTES,
        label="candidate checksums",
    )
    try:
        sums_text = sums_snapshot.data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CandidateAttestationError("candidate checksums are not ASCII") from exc
    _require(sums_text.endswith("\n"), "candidate checksums lack final newline")
    parsed: dict[str, str] = {}
    for line in sums_text.splitlines():
        parts = line.split("  ", 1)
        _require(len(parts) == 2, "candidate checksum line is malformed")
        digest, name = parts
        _require(
            HEX_64.fullmatch(digest) is not None
            and name in PLATFORM_CANDIDATE_ASSETS
            and name not in parsed,
            "candidate checksum entry is invalid",
        )
        parsed[name] = digest
    _require(
        list(parsed) == sorted(parsed)
        and set(parsed) == set(PLATFORM_CANDIDATE_ASSETS),
        "candidate checksums are incomplete or not canonical",
    )

    files: list[CandidateFile] = []
    for name in PLATFORM_CANDIDATE_ASSETS:
        asset = _snapshot_file(
            root / name,
            maximum=MAX_ASSET_BYTES,
            label=f"candidate asset {name}",
        )
        _require(asset.size > 0, f"candidate asset is empty: {name}")
        _require(parsed[name] == asset.sha256, f"candidate checksum differs: {name}")
        files.append(CandidateFile(name, asset.size, asset.sha256))
    _require(sums_snapshot.size > 0, "candidate checksums are empty")
    files.append(CandidateFile(sums_name, sums_snapshot.size, sums_snapshot.sha256))
    gate_snapshot = _snapshot_file(
        root / SOURCE_SECURITY_GATE,
        maximum=MAX_SECURITY_GATE_BYTES,
        label="candidate source security gate",
    )
    _require(gate_snapshot.size > 0, "candidate source security gate is empty")
    files.append(
        CandidateFile(
            SOURCE_SECURITY_GATE,
            gate_snapshot.size,
            gate_snapshot.sha256,
        )
    )
    return CandidateSnapshot(tuple(files))


def snapshot_candidate(path: pathlib.Path) -> CandidateSnapshot:
    """Sample and fully checksum the fixed candidate set."""

    return _snapshot_candidate_root(_candidate_directory(path))


def _parse_snapshot_document(value: object) -> CandidateSnapshot:
    document = _object(value, "candidate snapshot")
    _exact_keys(
        document,
        frozenset({"files", "kind", "schema_version"}),
        "candidate snapshot",
    )
    _require(
        type(document["schema_version"]) is int
        and document["schema_version"] == SNAPSHOT_SCHEMA_VERSION
        and document["kind"] == SNAPSHOT_KIND,
        "candidate snapshot identity differs",
    )
    raw_files = document["files"]
    _require(isinstance(raw_files, list), "candidate snapshot files are not a list")
    _require(
        len(raw_files) == len(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
        "candidate snapshot file count differs",
    )
    files: list[CandidateFile] = []
    for index, raw_file in enumerate(raw_files):
        record = _object(raw_file, "candidate snapshot file")
        _exact_keys(
            record,
            frozenset({"bytes", "name", "sha256"}),
            "candidate snapshot file",
        )
        expected_name = PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS[index]
        _require(record["name"] == expected_name, "candidate snapshot order differs")
        _require(
            type(record["bytes"]) is int and record["bytes"] > 0,
            "candidate snapshot size is invalid",
        )
        _require(
            isinstance(record["sha256"], str)
            and HEX_64.fullmatch(record["sha256"]) is not None,
            "candidate snapshot digest is invalid",
        )
        files.append(
            CandidateFile(expected_name, record["bytes"], record["sha256"])
        )
    return CandidateSnapshot(tuple(files))


def load_candidate_snapshot(path: pathlib.Path) -> CandidateSnapshot:
    """Load one private preflight snapshot through strict JSON parsing."""

    path = _normalize_fixed_output_path(
        path,
        safe_root=CANDIDATE_RAW_ROOT,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate preflight snapshot",
    )
    raw = _snapshot_file(
        path,
        maximum=MAX_SNAPSHOT_BYTES,
        label="candidate preflight snapshot",
        private=True,
    )
    try:
        value = parse_strict_json_bytes(raw.data, label="candidate preflight snapshot")
    except EvidenceIOError as exc:
        raise CandidateAttestationError("candidate snapshot JSON is invalid") from exc
    return _parse_snapshot_document(value)


def _private_directory(path: pathlib.Path, label: str) -> int:
    _require(path.is_absolute(), f"{label} must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CandidateAttestationError(f"cannot inspect {label}") from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"{label} is not a private non-symlink directory",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateAttestationError(f"cannot open {label}") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
    ):
        os.close(descriptor)
        _fail(f"{label} identity changed")
    return descriptor


@contextlib.contextmanager
def _private_directory_handle(path: pathlib.Path, label: str) -> Iterator[int]:
    """Close a pinned directory without replacing the primary exception."""

    descriptor = _private_directory(path, label)
    primary: BaseException | None = None
    try:
        yield descriptor
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            detail = f"cannot close {label}"
            if primary is not None:
                primary.add_note(detail)
            else:
                raise CandidateAttestationError(detail) from exc


def _normalize_fixed_output_path(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    expected_name: str,
    label: str,
) -> pathlib.Path:
    """Normalize one absent fixed-leaf output below a private direct child."""

    _require(path.is_absolute(), f"{label} must be absolute")
    _require(path.name == expected_name, f"{label} leaf differs")
    parent, root = _normalize_path_under_root(
        path.parent,
        safe_root=safe_root,
        label=f"{label} parent",
        required_root_mode=0o700,
    )
    _require(parent.parent == root, f"{label} parent must be a direct safe-root child")
    normalized = parent / expected_name
    if os.path.realpath(os.fspath(normalized)) != os.fspath(normalized):
        raise CandidateAttestationError(
            f"{label} must contain no symlink aliases"
        )
    return normalized


def _validate_output_absent(
    path: pathlib.Path,
    *,
    expected_name: str,
    label: str,
) -> None:
    with _private_directory_handle(
        path.parent, f"{label} parent"
    ) as parent_fd:
        try:
            os.stat(expected_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CandidateAttestationError(f"cannot inspect {label}") from exc
        _fail(f"{label} already exists")


def _validate_projection_target(
    candidate: pathlib.Path, projection_path: pathlib.Path
) -> tuple[pathlib.Path, pathlib.Path]:
    """Require the projection tree to be disjoint from candidate source bytes."""

    candidate_root = _candidate_directory(candidate)
    normalized_projection = _normalize_fixed_output_path(
        projection_path,
        safe_root=CANDIDATE_PROJECTION_ROOT,
        expected_name=PROJECTION_NAME,
        label="candidate projection",
    )
    projection_parent = normalized_projection.parent
    try:
        projection_parent.relative_to(candidate_root)
    except ValueError:
        pass
    else:
        _fail("candidate projection parent is inside the candidate directory")
    _validate_output_absent(
        normalized_projection,
        expected_name=PROJECTION_NAME,
        label="candidate projection",
    )
    return candidate_root, normalized_projection


def _write_private_json(
    path: pathlib.Path, expected_name: str, value: object, label: str
) -> str:
    _validate_output_absent(path, expected_name=expected_name, label=label)
    with _private_directory_handle(
        path.parent, f"{label} parent"
    ) as parent_fd:
        try:
            return write_private_json_noreplace_at(
                parent_fd,
                expected_name,
                value,
                label=label,
                maximum=MAX_SNAPSHOT_BYTES,
            )
        except PublicationReceiptIOError as exc:
            raise CandidateAttestationError(str(exc)) from exc


def write_candidate_snapshot(
    candidate: pathlib.Path,
    snapshot_path: pathlib.Path,
    projection_path: pathlib.Path,
    expected_commit: str | None = None,
) -> None:
    """Capture preflight bytes and prevalidate the explicit projection target."""

    candidate_root, projection_path = _validate_projection_target(
        candidate,
        projection_path,
    )
    if expected_commit is not None:
        _security_gate_projection(candidate_root, expected_commit)
    snapshot_path = _normalize_fixed_output_path(
        snapshot_path,
        safe_root=CANDIDATE_RAW_ROOT,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate snapshot",
    )
    _validate_output_absent(
        snapshot_path,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate snapshot",
    )
    snapshot = _snapshot_candidate_root(candidate_root)
    _write_private_json(
        snapshot_path,
        CANDIDATE_SNAPSHOT_NAME,
        snapshot.document(),
        "candidate snapshot",
    )


def collect_candidate_attestations(
    candidate: pathlib.Path,
    expected_commit: str,
    attestation_directory: pathlib.Path,
    *,
    source_environment: Mapping[str, str] | None = None,
) -> None:
    """Collect six bounded candidate verification results with the pinned CLI."""

    _require(HEX_40.fullmatch(expected_commit) is not None, "expected commit is malformed")
    candidate_root = _candidate_directory(candidate)
    normalized, raw_root = _normalize_path_under_root(
        attestation_directory,
        safe_root=CANDIDATE_RAW_ROOT,
        label="candidate attestation directory",
        required_root_mode=0o700,
    )
    _require(
        normalized.parent == raw_root
        and SAFE_DIRECTORY_LEAF.fullmatch(normalized.name) is not None,
        "candidate attestation directory is not a safe direct child",
    )
    with _private_directory_handle(
        normalized,
        "candidate attestation directory",
    ) as descriptor:
        try:
            existing = set(os.listdir(descriptor))
        except OSError as exc:
            raise CandidateAttestationError(
                "cannot enumerate candidate attestation directory"
            ) from exc
        _require(
            existing == {CANDIDATE_SNAPSHOT_NAME},
            "candidate attestation directory is not at its preflight state",
        )
        _snapshot_file(
            normalized / CANDIDATE_SNAPSHOT_NAME,
            maximum=MAX_SNAPSHOT_BYTES,
            label="candidate preflight snapshot",
            private=True,
        )
        try:
            environment = github_release.github_cli_environment(
                os.environ if source_environment is None else source_environment
            )
            tool = github_release.select_github_cli()
            for subject in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:
                payload = github_release.capture_github_cli(
                    tool,
                    [
                        "attestation",
                        "verify",
                        str(candidate_root / subject),
                        "--repo",
                        REPOSITORY,
                        "--signer-workflow",
                        f"{REPOSITORY}/{WORKFLOW_PATH}",
                        "--signer-digest",
                        expected_commit,
                        "--source-ref",
                        RELEASE_REF,
                        "--source-digest",
                        expected_commit,
                        "--deny-self-hosted-runners",
                        "--format",
                        "json",
                    ],
                    timeout_seconds=120,
                    maximum_bytes=MAX_ATTESTATION_BYTES,
                    environment=environment,
                    label=f"GitHub candidate attestation for {subject}",
                )
                write_private_bytes_noreplace_at(
                    descriptor,
                    f"{subject}.json",
                    payload,
                    label=f"raw candidate attestation for {subject}",
                    maximum=MAX_ATTESTATION_BYTES,
                )
        except github_release.GitHubReleaseObservationError as exc:
            raise CandidateAttestationError(str(exc)) from exc
        except PublicationReceiptIOError as exc:
            raise CandidateAttestationError(str(exc)) from exc


def verify_candidate_checkout(
    expected_commit: str,
    *,
    expected_source_parent: str | None = None,
    include_untracked: bool = True,
    source_environment: Mapping[str, str] | None = None,
) -> str:
    """Verify the exact annotated-tag checkout with fixed Git and no ambient config."""

    _require(HEX_40.fullmatch(expected_commit) is not None, "expected commit is malformed")
    if expected_source_parent is not None:
        _require(
            HEX_40.fullmatch(expected_source_parent) is not None,
            "expected source parent is malformed",
        )
        _require(
            expected_source_parent != expected_commit,
            "source parent must differ from the candidate commit",
        )
    source = os.environ if source_environment is None else source_environment
    _require(
        not any(name.startswith("GIT_") for name in source),
        "candidate checkout rejects caller Git environment overrides",
    )
    environment = github_release.git_observation_environment()
    base = [
        GIT,
        "-C",
        str(REPOSITORY_ROOT),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
    ]

    def git_output(arguments: Sequence[str], *, label: str) -> bytes:
        try:
            result = capture_stdout(
                [*base, *arguments],
                timeout_seconds=30,
                maximum_bytes=MAX_GIT_OUTPUT_BYTES,
                stderr=subprocess.DEVNULL,
                environment=environment,
            )
        except BoundedProcessError as exc:
            raise CandidateAttestationError(f"{label} failed safely") from exc
        _require(result.returncode == 0, f"{label} was rejected")
        return result.stdout

    def git_line(arguments: Sequence[str], *, label: str) -> str:
        raw = git_output(arguments, label=label)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise CandidateAttestationError(f"{label} is not ASCII") from exc
        _require(
            text.endswith("\n") and text.count("\n") == 1,
            f"{label} output differs",
        )
        return text[:-1]

    release_ref = f"refs/tags/{RELEASE_TAG}"
    _require(
        git_line(["cat-file", "-t", release_ref], label="platform release tag type")
        == "tag",
        "platform release tag is not annotated",
    )
    for arguments, label in (
        (["rev-parse", "--verify", f"{release_ref}^{{commit}}"], "tag commit"),
        (["rev-parse", "--verify", "HEAD^{commit}"], "checkout commit"),
        (
            ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
            "origin/main commit",
        ),
    ):
        _require(
            git_line(arguments, label=f"platform {label}") == expected_commit,
            f"platform {label} differs from the expected candidate commit",
        )
    if expected_source_parent is not None:
        _require(
            git_line(
                ["rev-list", "--parents", "-n", "1", expected_commit],
                label="platform candidate parent",
            )
            == f"{expected_commit} {expected_source_parent}",
            "platform candidate is not the direct results-only child of S",
        )
        _require(
            git_output(
                [
                    "diff",
                    "--name-only",
                    expected_source_parent,
                    expected_commit,
                    "--",
                ],
                label="platform candidate changed paths",
            )
            == b"artifact/results.json\n",
            "platform candidate changed paths differ from artifact/results.json",
        )
    _require(
        git_output(
            [
                "status",
                "--porcelain=v1",
                f"--untracked-files={'all' if include_untracked else 'no'}",
            ],
            label="platform candidate worktree status",
        )
        == b"",
        "candidate verification requires a clean worktree",
    )
    source_epoch = git_line(
        ["show", "-s", "--format=%ct", expected_commit],
        label="platform candidate source epoch",
    )
    _require(
        re.fullmatch(r"[1-9][0-9]{0,11}", source_epoch) is not None
        and int(source_epoch) <= 253_402_300_799,
        "platform candidate source epoch is malformed",
    )
    return source_epoch


def preflight_candidate_paths(
    candidate: pathlib.Path,
    projection_path: pathlib.Path,
    expected_commit: str | None = None,
) -> None:
    """Validate caller-controlled paths before the shell invokes Git or GitHub."""

    candidate_root, _projection = _validate_projection_target(candidate, projection_path)
    if expected_commit is not None:
        _security_gate_projection(candidate_root, expected_commit)


def _utc_timestamp(value: object) -> str:
    _require(
        isinstance(value, str) and STRICT_TIMESTAMP.fullmatch(value) is not None,
        "verified timestamp is malformed",
    )
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateAttestationError("verified timestamp is malformed") from exc
    _require(parsed.tzinfo is not None, "verified timestamp lacks a timezone")
    return parsed.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bounded_positive_decimal(value: str, *, maximum: int, label: str) -> int:
    """Parse a positive decimal without exposing Python's unbounded-int limit."""

    maximum_text = str(maximum)
    _require(
        len(value) <= len(maximum_text)
        and re.fullmatch(r"[1-9][0-9]*", value) is not None
        and (len(value) < len(maximum_text) or value <= maximum_text),
        f"{label} is out of range",
    )
    return int(value)


def _verification_record(
    path: pathlib.Path,
    *,
    asset: str,
    expected_commit: str,
    expected_subjects: list[dict[str, object]],
) -> VerifiedRecord:
    raw = _snapshot_file(
        path,
        maximum=MAX_ATTESTATION_BYTES,
        label=f"raw attestation for {asset}",
        private=True,
    )
    try:
        value = parse_strict_json_bytes(raw.data, label=f"attestation for {asset}")
    except EvidenceIOError as exc:
        raise CandidateAttestationError(
            f"attestation JSON is invalid for {asset}"
        ) from exc
    _require(
        isinstance(value, list) and len(value) == 1,
        f"attestation result count differs for {asset}",
    )
    envelope = _object(value[0], f"attestation envelope for {asset}")
    _exact_keys(
        envelope,
        frozenset({"attestation", "verificationResult"}),
        "attestation envelope",
    )
    _require(
        isinstance(envelope["attestation"], dict),
        "attestation bundle is not an object",
    )
    result = _object(envelope["verificationResult"], "verification result")
    _exact_keys(
        result,
        frozenset(
            {
                "mediaType",
                "signature",
                "statement",
                "verifiedIdentity",
                "verifiedTimestamps",
            }
        ),
        "verification result",
    )
    _require(
        result["mediaType"] == VERIFICATION_MEDIA_TYPE,
        "verification result media type differs",
    )

    statement = _object(result["statement"], "attestation statement")
    _exact_keys(
        statement,
        frozenset({"_type", "predicate", "predicateType", "subject"}),
        "attestation statement",
    )
    _require(statement["_type"] == STATEMENT_TYPE, "attestation statement type differs")
    _require(
        statement["predicateType"] == PREDICATE_TYPE,
        "attestation predicate type differs",
    )
    _require(
        statement["subject"] == expected_subjects,
        "attestation subjects differ from candidate bytes",
    )

    predicate = _object(statement["predicate"], "attestation predicate")
    _exact_keys(
        predicate,
        frozenset({"buildDefinition", "runDetails"}),
        "attestation predicate",
    )
    build = _object(predicate["buildDefinition"], "attestation build definition")
    _exact_keys(
        build,
        frozenset(
            {
                "buildType",
                "externalParameters",
                "internalParameters",
                "resolvedDependencies",
            }
        ),
        "attestation build definition",
    )
    _require(
        build["buildType"] == "https://actions.github.io/buildtypes/workflow/v1",
        "attestation build type differs",
    )
    _require(
        build["externalParameters"]
        == {
            "workflow": {
                "path": WORKFLOW_PATH,
                "ref": RELEASE_REF,
                "repository": REPOSITORY_URL,
            }
        },
        "attestation workflow parameters differ",
    )
    internal = _object(build["internalParameters"], "attestation internal parameters")
    _exact_keys(
        internal, frozenset({"github"}), "attestation internal parameters"
    )
    github = _object(internal["github"], "attestation GitHub parameters")
    _exact_keys(
        github,
        frozenset(
            {
                "event_name",
                "repository_id",
                "repository_owner_id",
                "runner_environment",
            }
        ),
        "attestation GitHub parameters",
    )
    _require(
        github["event_name"] == "push"
        and github["runner_environment"] == "github-hosted"
        and isinstance(github["repository_id"], str)
        and re.fullmatch(r"[1-9][0-9]*", github["repository_id"]) is not None
        and isinstance(github["repository_owner_id"], str)
        and re.fullmatch(r"[1-9][0-9]*", github["repository_owner_id"]) is not None,
        "attestation GitHub execution identity differs",
    )
    _require(
        build["resolvedDependencies"]
        == [
            {
                "digest": {"gitCommit": expected_commit},
                "uri": f"git+{REPOSITORY_URL}@{RELEASE_REF}",
            }
        ],
        "attestation source dependency differs",
    )

    signature = _object(result["signature"], "attestation signature")
    _exact_keys(signature, frozenset({"certificate"}), "attestation signature")
    certificate = _object(signature["certificate"], "attestation certificate")
    certificate_keys = frozenset(
        {
            "buildConfigDigest",
            "buildConfigURI",
            "buildSignerDigest",
            "buildSignerURI",
            "buildTrigger",
            "certificateIssuer",
            "githubWorkflowName",
            "githubWorkflowRef",
            "githubWorkflowRepository",
            "githubWorkflowSHA",
            "githubWorkflowTrigger",
            "issuer",
            "runInvocationURI",
            "runnerEnvironment",
            "sourceRepositoryDigest",
            "sourceRepositoryIdentifier",
            "sourceRepositoryOwnerIdentifier",
            "sourceRepositoryOwnerURI",
            "sourceRepositoryRef",
            "sourceRepositoryURI",
            "sourceRepositoryVisibilityAtSigning",
            "subjectAlternativeName",
        }
    )
    _exact_keys(certificate, certificate_keys, "attestation certificate")
    fixed_certificate = {
        "buildConfigDigest": expected_commit,
        "buildConfigURI": WORKFLOW_URI,
        "buildSignerDigest": expected_commit,
        "buildSignerURI": WORKFLOW_URI,
        "buildTrigger": "push",
        "certificateIssuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowName": "ABI2 stable platform release",
        "githubWorkflowRef": RELEASE_REF,
        "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowSHA": expected_commit,
        "githubWorkflowTrigger": "push",
        "issuer": "https://fulcio.sigstore.dev",
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryDigest": expected_commit,
        "sourceRepositoryIdentifier": github["repository_id"],
        "sourceRepositoryOwnerIdentifier": github["repository_owner_id"],
        "sourceRepositoryOwnerURI": REPOSITORY_OWNER_URL,
        "sourceRepositoryRef": RELEASE_REF,
        "sourceRepositoryURI": REPOSITORY_URL,
        "sourceRepositoryVisibilityAtSigning": "public",
        "subjectAlternativeName": WORKFLOW_URI,
    }
    for key, expected in fixed_certificate.items():
        _require(certificate[key] == expected, f"attestation certificate {key} differs")
    run_uri = certificate["runInvocationURI"]
    _require(isinstance(run_uri, str), "attestation run URI is not a string")
    run_match = re.fullmatch(
        re.escape(RUN_URI_PREFIX)
        + r"([1-9][0-9]*)/attempts/([1-9][0-9]*)",
        run_uri,
    )
    _require(run_match is not None, "attestation run URI is malformed")
    run_id = _bounded_positive_decimal(
        run_match.group(1),
        maximum=MAX_RUN_ID,
        label="attestation run ID",
    )
    run_attempt = _bounded_positive_decimal(
        run_match.group(2),
        maximum=MAX_RUN_ATTEMPT,
        label="attestation run attempt",
    )

    run_details = _object(predicate["runDetails"], "attestation run details")
    _require(
        run_details
        == {
            "builder": {"id": WORKFLOW_URI},
            "metadata": {"invocationId": run_uri},
        },
        "attestation run details differ",
    )
    _require(
        result["verifiedIdentity"]
        == {
            "issuer": {"issuer": "", "regexp": ".*"},
            "runnerEnvironment": "github-hosted",
            "subjectAlternativeName": {
                "regexp": f"^{REPOSITORY_URL}/{WORKFLOW_PATH}",
                "subjectAlternativeName": "",
            },
        },
        "verified attestation identity differs",
    )
    timestamps = result["verifiedTimestamps"]
    _require(
        isinstance(timestamps, list) and len(timestamps) == 1,
        "verified timestamp count differs",
    )
    timestamp = _object(timestamps[0], "verified timestamp")
    _require(
        timestamp.get("type") == "Tlog"
        and timestamp.get("uri") == "https://rekor.sigstore.dev"
        and frozenset(timestamp) == frozenset({"timestamp", "type", "uri"}),
        "verified timestamp identity differs",
    )
    verified_at = _utc_timestamp(timestamp["timestamp"])
    timestamp["timestamp"] = verified_at
    return VerifiedRecord(
        statement=_canonical_json(statement),
        record=_canonical_json(result),
        run_id=run_id,
        run_attempt=run_attempt,
        verified_at=verified_at,
    )


def _raw_attestation_directory(path: pathlib.Path) -> pathlib.Path:
    normalized, root = _normalize_path_under_root(
        path,
        safe_root=CANDIDATE_RAW_ROOT,
        label="candidate attestation directory",
        required_root_mode=0o700,
    )
    _require(
        normalized.parent == root,
        "candidate attestation directory must be a direct safe-root child",
    )
    _require(
        SAFE_DIRECTORY_LEAF.fullmatch(normalized.name) is not None,
        "candidate attestation directory leaf is unsafe",
    )
    expected = {CANDIDATE_SNAPSHOT_NAME}
    for subject in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:
        expected.add(f"{subject}.json")
    with _private_directory_handle(
        normalized, "candidate attestation directory"
    ) as descriptor:
        try:
            actual = set(os.listdir(descriptor))
        except OSError as exc:
            raise CandidateAttestationError(
                "cannot enumerate candidate attestation directory"
            ) from exc
    _require(actual == expected, "candidate attestation file set differs")
    return normalized


def _security_gate_projection(
    candidate: pathlib.Path, expected_commit: str
) -> dict[str, object]:
    _require(
        HEX_40.fullmatch(expected_commit) is not None,
        "source security gate expected commit is malformed",
    )
    snapshot = _snapshot_file(
        candidate / SOURCE_SECURITY_GATE,
        maximum=MAX_SECURITY_GATE_BYTES,
        label="candidate source security gate",
    )
    try:
        value = parse_strict_json_bytes(
            snapshot.data,
            label="candidate source security gate",
        )
    except EvidenceIOError as exc:
        raise CandidateAttestationError(
            "candidate source security gate JSON is invalid"
        ) from exc
    source_parent = _source_parent_from_results()
    ci_sha256 = _workflow_sha256(CI_WORKFLOW_PATH, label="CI workflow source")
    codeql_sha256 = _workflow_sha256(
        CODEQL_WORKFLOW_PATH,
        label="CodeQL workflow source",
    )
    try:
        gate = validate_source_security_gate(
            value,
            expected_tag_commit=expected_commit,
            expected_source_parent_commit=source_parent,
            expected_ci_workflow_sha256=ci_sha256,
            expected_codeql_workflow_sha256=codeql_sha256,
        )
    except PlatformDistributionContractError as exc:
        raise CandidateAttestationError(str(exc)) from exc
    return {"receipt_sha256": snapshot.sha256, **gate}


def verify_candidate_attestations(
    candidate: pathlib.Path,
    expected_commit: str,
    projection_path: pathlib.Path,
    attestation_dir: pathlib.Path,
    preflight_snapshot_path: pathlib.Path,
) -> tuple[str, int]:
    """Re-snapshot candidate bytes, verify six records, and publish projection."""

    _require(HEX_40.fullmatch(expected_commit) is not None, "expected commit is malformed")
    candidate, projection_path = _validate_projection_target(
        candidate,
        projection_path,
    )
    attestation_dir = _raw_attestation_directory(attestation_dir)
    preflight_snapshot_path = _normalize_fixed_output_path(
        preflight_snapshot_path,
        safe_root=CANDIDATE_RAW_ROOT,
        expected_name=CANDIDATE_SNAPSHOT_NAME,
        label="candidate preflight snapshot",
    )
    _require(
        preflight_snapshot_path == attestation_dir / CANDIDATE_SNAPSHOT_NAME,
        "candidate preflight snapshot path differs",
    )
    preflight = load_candidate_snapshot(preflight_snapshot_path)
    post_gh = _snapshot_candidate_root(candidate)
    _require(
        post_gh.document() == preflight.document(),
        "candidate bytes changed during GitHub verification",
    )
    expected_subjects = preflight.subjects()
    security_gate = _security_gate_projection(candidate, expected_commit)
    gate_subject = next(
        (
            subject
            for subject in expected_subjects
            if subject.get("name") == SOURCE_SECURITY_GATE
        ),
        None,
    )
    _require(gate_subject is not None, "source security gate subject is absent")
    gate_digest = _object(gate_subject.get("digest"), "source security gate subject digest")
    _require(
        gate_digest == {"sha256": security_gate["receipt_sha256"]},
        "source security gate projection differs from its attested subject",
    )

    shared: VerifiedRecord | None = None
    for asset in PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS:
        record = _verification_record(
            attestation_dir / f"{asset}.json",
            asset=asset,
            expected_commit=expected_commit,
            expected_subjects=expected_subjects,
        )
        if shared is None:
            shared = record
        else:
            _require(record.statement == shared.statement, "candidate statements differ")
            _require(record.record == shared.record, "candidate records differ")
            _require(record.run_id == shared.run_id, "candidate run IDs differ")
            _require(
                record.run_attempt == shared.run_attempt,
                "candidate run attempts differ",
            )
            _require(
                record.verified_at == shared.verified_at,
                "candidate verification timestamps differ",
            )
    _require(shared is not None, "candidate verification result set is empty")

    projection: dict[str, object] = {
        "certificate_san": WORKFLOW_URI,
        "predicate_type": PREDICATE_TYPE,
        "security_gate": security_gate,
        "signer_workflow": WORKFLOW_URI,
        "source_digest": expected_commit,
        "source_ref": RELEASE_REF,
        "subjects": expected_subjects,
        "verification_record_sha256": hashlib.sha256(shared.record).hexdigest(),
        "verified": True,
        "verified_at": shared.verified_at,
        "workflow_run_attempt": shared.run_attempt,
        "workflow_run_id": shared.run_id,
    }
    projection_sha256 = _write_private_json(
        projection_path,
        PROJECTION_NAME,
        projection,
        "candidate projection",
    )
    return projection_sha256, shared.run_id


def _usage() -> str:
    return (
        "usage: platform_candidate_attestation.py release-tag | subject-names | "
        "validate-raw-root | "
        "security-gate CI_RUNS CI_JOBS CODEQL_RUNS CODEQL_JOBS R S OUTPUT "
        "GH_SHA256 GH_VERSION | "
        "security-gate-live R S OUTPUT | "
        "pretag-security-readiness R S | "
        "stable-source-currentness EXPECTED_SOURCE_PARENT | "
        "checkout-verify EXPECTED_COMMIT | "
        "checkout-verify-release EXPECTED_COMMIT EXPECTED_SOURCE_PARENT | "
        "checkout-verify-tracked EXPECTED_COMMIT | "
        "github-verify CANDIDATE_DIRECTORY EXPECTED_COMMIT RAW_DIRECTORY | "
        "preflight CANDIDATE_DIRECTORY PROJECTION_OUTPUT EXPECTED_COMMIT | "
        "snapshot CANDIDATE_DIRECTORY SNAPSHOT_OUTPUT PROJECTION_OUTPUT "
        "EXPECTED_COMMIT | "
        "verify CANDIDATE_DIRECTORY EXPECTED_COMMIT PROJECTION_OUTPUT "
        "RAW_ATTESTATION_DIRECTORY SNAPSHOT_INPUT"
    )


def _main(arguments: Sequence[str]) -> int:
    if list(arguments) == ["release-tag"]:
        print(RELEASE_TAG)
        return 0
    if list(arguments) == ["subject-names"]:
        print("\n".join(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS))
        return 0
    if list(arguments) == ["validate-raw-root"]:
        _normalized_safe_root(
            CANDIDATE_VERIFICATION_ROOT,
            label="candidate verification",
            required_mode=0o700,
        )
        _normalized_safe_root(
            CANDIDATE_RAW_ROOT,
            label="candidate attestation",
            required_mode=0o700,
        )
        return 0
    if len(arguments) == 10 and arguments[0] == "security-gate":
        digest = assemble_source_security_gate(
            pathlib.Path(arguments[1]),
            pathlib.Path(arguments[2]),
            pathlib.Path(arguments[3]),
            pathlib.Path(arguments[4]),
            arguments[5],
            arguments[6],
            pathlib.Path(arguments[7]),
            arguments[8],
            arguments[9],
        )
        print(
            "ABI2_SOURCE_SECURITY_GATE_PASS "
            f"sha256={digest} tag_commit={arguments[5]}"
        )
        return 0
    if len(arguments) == 4 and arguments[0] == "security-gate-live":
        digest = assemble_live_source_security_gate(
            arguments[1],
            arguments[2],
            pathlib.Path(arguments[3]),
        )
        print(
            "ABI2_SOURCE_SECURITY_GATE_PASS "
            f"sha256={digest} tag_commit={arguments[1]}"
        )
        return 0
    if len(arguments) == 3 and arguments[0] == "pretag-security-readiness":
        ci_run, ci_attempt, codeql_run, codeql_attempt, tool_sha256 = (
            verify_pretag_security_readiness(arguments[1], arguments[2])
        )
        print(
            "PRETAG_SECURITY_READINESS_PASS "
            f"tag_commit={arguments[1]} source_parent={arguments[2]} "
            f"ci_run={ci_run} ci_attempt={ci_attempt} "
            f"codeql_run={codeql_run} codeql_attempt={codeql_attempt} "
            f"github_cli_sha256={tool_sha256}"
        )
        return 0
    if len(arguments) == 4 and arguments[0] == "github-verify":
        collect_candidate_attestations(
            pathlib.Path(arguments[1]),
            arguments[2],
            pathlib.Path(arguments[3]),
        )
        return 0
    if len(arguments) == 2 and arguments[0] == "checkout-verify":
        verify_candidate_checkout(arguments[1])
        return 0
    if len(arguments) == 3 and arguments[0] == "checkout-verify-release":
        verify_candidate_checkout(
            arguments[1],
            expected_source_parent=arguments[2],
        )
        return 0
    if len(arguments) == 2 and arguments[0] == "checkout-verify-tracked":
        print(verify_candidate_checkout(arguments[1], include_untracked=False))
        return 0
    if len(arguments) == 2 and arguments[0] == "stable-source-currentness":
        validate_tag_source_currentness(arguments[1])
        return 0
    if len(arguments) == 4 and arguments[0] == "preflight":
        preflight_candidate_paths(
            pathlib.Path(arguments[1]),
            pathlib.Path(arguments[2]),
            arguments[3],
        )
        return 0
    if len(arguments) == 5 and arguments[0] == "snapshot":
        write_candidate_snapshot(
            pathlib.Path(arguments[1]),
            pathlib.Path(arguments[2]),
            pathlib.Path(arguments[3]),
            arguments[4],
        )
        return 0
    if len(arguments) == 6 and arguments[0] == "verify":
        digest, run_id = verify_candidate_attestations(
            pathlib.Path(arguments[1]),
            arguments[2],
            pathlib.Path(arguments[3]),
            pathlib.Path(arguments[4]),
            pathlib.Path(arguments[5]),
        )
        print(
            "ABI2_PLATFORM_CANDIDATE_ATTESTATION_VERIFY_PASS "
            f"assets={len(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS)} "
            f"commit={arguments[2]} "
            f"projection_sha256={digest} run_id={run_id}"
        )
        return 0
    print(f"error: {_usage()}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except PublicationReceiptCommittedError as exc:
        detail = f"visibility={exc.visibility}"
        if exc.leaf is not None and exc.digest is not None:
            detail += f" leaf={exc.leaf} sha256={exc.digest}"
        raise SystemExit(
            f"error: source security gate publication {detail}"
        ) from None
    except CandidateAttestationError as exc:
        raise SystemExit(f"error: {exc}") from None
