#!/usr/bin/env python3
"""Current ABI2 0.1.0 platform-distribution identity and asset contract.

This module contains only prepublication identity: product/revision names, the
exact asset inventory, and the source-security gate schema consumed by the
candidate producer.  Published asset hashes and release observations belong to
the separate immutable publication-receipt contract and must never be
introduced here, because the current producer has to exist before those values
do.
"""

from __future__ import annotations

import re
from typing import Any, NoReturn


PLATFORM_DISTRIBUTION_SCHEMA_VERSION = 1
PLATFORM_DISTRIBUTION_KIND = "qperiapt.abi2_platform_distribution"
ANDROID_DEVICE_PROOF_SCHEMA_VERSION = 6

PRODUCT_VERSION = "0.1.0"
DISTRIBUTION_REVISION = "r1"
RELEASE_TAG = f"abi2-platforms-v{PRODUCT_VERSION}"
RELEASE_URL = f"https://github.com/billlza/q-periapt/releases/tag/{RELEASE_TAG}"

RELEASE_MANIFEST = "PLATFORM_DISTRIBUTION.json"
RELEASE_SUMS = "SHA256SUMS"
CANDIDATE_SUMS = "CANDIDATE_SHA256SUMS"
SOURCE_SECURITY_GATE = "ABI2_SOURCE_SECURITY_GATE.json"
SOURCE_SECURITY_GATE_SCHEMA_VERSION = 1
SOURCE_SECURITY_GATE_KIND = "qperiapt.abi2_source_security_gate"
REPOSITORY = "billlza/q-periapt"
CI_WORKFLOW_NAME = "ci"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
CODEQL_WORKFLOW_NAME = "CodeQL"
CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"
MAX_WORKFLOW_RUN_ID = (1 << 63) - 1
MAX_WORKFLOW_RUN_ATTEMPT = (1 << 31) - 1

CONSTANT_TIME_JOB_CONTRACT = (
    ("x86_64", "portable-c", "Binary CT [x86_64-portable]"),
    ("aarch64", "aarch64-native", "Binary CT [aarch64-native]"),
)
CODEQL_JOB_CONTRACT = tuple(
    (language, f"Analyze ({language})")
    for language in (
        "actions",
        "c-cpp",
        "java-kotlin",
        "python",
        "rust",
        "swift",
    )
)

ANDROID_AAR = f"q-periapt-android-{PRODUCT_VERSION}.aar"
ANDROID_MANIFEST = f"q-periapt-android-{PRODUCT_VERSION}-MANIFEST.json"
ANDROID_RUNTIME_BUNDLE = (
    f"q-periapt-android-{PRODUCT_VERSION}-16k-runtime-evidence.zip"
)
LINUX_X86_64 = (
    f"q-periapt-c-abi2-{PRODUCT_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
)
LINUX_AARCH64 = (
    f"q-periapt-c-abi2-{PRODUCT_VERSION}-aarch64-unknown-linux-gnu.tar.gz"
)
# Exact order used by the tag-bound candidate workflow and its one shared
# provenance statement.  The runtime bundle is assembled locally afterwards
# and therefore is deliberately absent from this CI-candidate set.
PLATFORM_CANDIDATE_ASSETS = (
    ANDROID_AAR,
    ANDROID_MANIFEST,
    LINUX_X86_64,
    LINUX_AARCH64,
)
PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS = (
    *PLATFORM_CANDIDATE_ASSETS,
    CANDIDATE_SUMS,
    SOURCE_SECURITY_GATE,
)

PLATFORM_INPUT_ASSETS = frozenset(
    {
        ANDROID_AAR,
        ANDROID_MANIFEST,
        ANDROID_RUNTIME_BUNDLE,
        LINUX_X86_64,
        LINUX_AARCH64,
    }
)
PLATFORM_RELEASE_FILES = PLATFORM_INPUT_ASSETS | {RELEASE_MANIFEST, RELEASE_SUMS}


_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GH_VERSION_RE = re.compile(
    r"^gh version [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?(?: \([^\r\n]{1,160}\))?$"
)


class PlatformDistributionContractError(ValueError):
    """A prepublication platform identity or security gate is malformed."""


def _fail(message: str) -> NoReturn:
    raise PlatformDistributionContractError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        f"{label} must be an object with string keys",
    )
    return value


def _exact_keys(
    value: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = frozenset(value)
    _require(
        actual == expected,
        f"{label} keys differ: missing={sorted(expected - actual)!r} "
        f"extra={sorted(actual - expected)!r}",
    )


def _sha1(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and _SHA1_RE.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-1",
    )
    return value


def _sha256(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-256",
    )
    return value


def _positive_integer(value: object, *, maximum: int, label: str) -> int:
    _require(
        type(value) is int and 0 < value <= maximum,
        f"{label} must be a bounded positive integer",
    )
    return value


def _validate_observation_tools(value: object) -> None:
    tools = _object(value, "source security gate observation tools")
    _exact_keys(
        tools,
        frozenset({"github_cli"}),
        "source security gate observation tools",
    )
    label = "source security gate gh tool"
    tool = _object(tools["github_cli"], label)
    _exact_keys(
        tool,
        frozenset({"name", "path", "sha256", "version"}),
        label,
    )
    _require(
        tool["name"] == "gh" and tool["path"] == "/usr/bin/gh",
        f"{label} identity differs",
    )
    _sha256(tool["sha256"], f"{label} digest")
    _require(
        isinstance(tool["version"], str)
        and tool["version"].isascii()
        and _GH_VERSION_RE.fullmatch(tool["version"]) is not None,
        f"{label} version differs",
    )


def _validate_workflow_run(
    value: object,
    *,
    label: str,
    workflow_name: str,
    workflow_path: str,
    expected_tag_commit: str,
    expected_workflow_sha256: str | None,
) -> dict[str, Any]:
    run = _object(value, label)
    _exact_keys(
        run,
        frozenset(
            {
                "conclusion",
                "event",
                "head_branch",
                "head_sha",
                "jobs",
                "run_attempt",
                "run_id",
                "status",
                "workflow_name",
                "workflow_path",
                "workflow_sha256",
            }
        ),
        label,
    )
    _require(run["workflow_name"] == workflow_name, f"{label} name differs")
    _require(run["workflow_path"] == workflow_path, f"{label} path differs")
    workflow_sha256 = _sha256(run["workflow_sha256"], f"{label} source")
    if expected_workflow_sha256 is not None:
        _require(
            workflow_sha256 == expected_workflow_sha256,
            f"{label} source digest differs from the verifier checkout",
        )
    _positive_integer(
        run["run_id"], maximum=MAX_WORKFLOW_RUN_ID, label=f"{label} run id"
    )
    _positive_integer(
        run["run_attempt"],
        maximum=MAX_WORKFLOW_RUN_ATTEMPT,
        label=f"{label} run attempt",
    )
    _require(
        run["head_sha"] == expected_tag_commit
        and run["head_branch"] == "main"
        and run["event"] == "push"
        and run["status"] == "completed"
        and run["conclusion"] == "success",
        f"{label} is not one exact successful main/push run at the tag commit",
    )
    return run


def _validate_constant_time_jobs(value: object) -> None:
    _require(isinstance(value, list), "constant-time jobs must be a list")
    _require(
        len(value) == len(CONSTANT_TIME_JOB_CONTRACT),
        "constant-time job count differs",
    )
    job_ids: set[int] = set()
    for index, (raw, expected) in enumerate(
        zip(value, CONSTANT_TIME_JOB_CONTRACT, strict=True)
    ):
        architecture, implementation, name = expected
        label = f"constant-time job {index}"
        job = _object(raw, label)
        _exact_keys(
            job,
            frozenset(
                {
                    "architecture",
                    "conclusion",
                    "implementation",
                    "job_id",
                    "name",
                    "status",
                }
            ),
            label,
        )
        job_id = _positive_integer(
            job["job_id"], maximum=MAX_WORKFLOW_RUN_ID, label=f"{label} id"
        )
        _require(job_id not in job_ids, "constant-time job ids are not unique")
        job_ids.add(job_id)
        _require(
            job
            == {
                "architecture": architecture,
                "conclusion": "success",
                "implementation": implementation,
                "job_id": job_id,
                "name": name,
                "status": "completed",
            },
            f"{label} identity or result differs",
        )


def _validate_codeql_jobs(value: object) -> None:
    _require(isinstance(value, list), "CodeQL jobs must be a list")
    _require(len(value) == len(CODEQL_JOB_CONTRACT), "CodeQL job count differs")
    job_ids: set[int] = set()
    for index, (raw, expected) in enumerate(
        zip(value, CODEQL_JOB_CONTRACT, strict=True)
    ):
        language, name = expected
        label = f"CodeQL job {index}"
        job = _object(raw, label)
        _exact_keys(
            job,
            frozenset(
                {"conclusion", "job_id", "language", "name", "status"}
            ),
            label,
        )
        job_id = _positive_integer(
            job["job_id"], maximum=MAX_WORKFLOW_RUN_ID, label=f"{label} id"
        )
        _require(job_id not in job_ids, "CodeQL job ids are not unique")
        job_ids.add(job_id)
        _require(
            job
            == {
                "conclusion": "success",
                "job_id": job_id,
                "language": language,
                "name": name,
                "status": "completed",
            },
            f"{label} identity or result differs",
        )


def validate_source_security_gate(
    value: object,
    *,
    expected_tag_commit: str | None = None,
    expected_source_parent_commit: str | None = None,
    expected_ci_workflow_sha256: str | None = None,
    expected_codeql_workflow_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate one exact-R CI/CodeQL gate without performing network I/O."""

    gate = _object(value, "source security gate")
    _exact_keys(
        gate,
        frozenset(
            {
                "kind",
                "observation_tools",
                "repository",
                "schema_version",
                "source_parent_commit",
                "tag_commit",
                "workflows",
            }
        ),
        "source security gate",
    )
    _require(
        type(gate["schema_version"]) is int
        and gate["schema_version"] == SOURCE_SECURITY_GATE_SCHEMA_VERSION,
        "source security gate schema differs",
    )
    _require(gate["kind"] == SOURCE_SECURITY_GATE_KIND, "source security gate kind differs")
    _require(gate["repository"] == REPOSITORY, "source security gate repository differs")
    _validate_observation_tools(gate["observation_tools"])
    tag_commit = _sha1(gate["tag_commit"], "source security gate tag commit")
    source_parent_commit = _sha1(
        gate["source_parent_commit"], "source security gate source parent"
    )
    _require(tag_commit != source_parent_commit, "source security gate R equals S")
    if expected_tag_commit is not None:
        _require(tag_commit == expected_tag_commit, "source security gate R differs")
    if expected_source_parent_commit is not None:
        _require(
            source_parent_commit == expected_source_parent_commit,
            "source security gate S differs",
        )
    workflows = _object(gate["workflows"], "source security gate workflows")
    _exact_keys(workflows, frozenset({"ci", "codeql"}), "source security gate workflows")
    ci = _validate_workflow_run(
        workflows["ci"],
        label="CI security run",
        workflow_name=CI_WORKFLOW_NAME,
        workflow_path=CI_WORKFLOW_PATH,
        expected_tag_commit=tag_commit,
        expected_workflow_sha256=expected_ci_workflow_sha256,
    )
    codeql = _validate_workflow_run(
        workflows["codeql"],
        label="CodeQL security run",
        workflow_name=CODEQL_WORKFLOW_NAME,
        workflow_path=CODEQL_WORKFLOW_PATH,
        expected_tag_commit=tag_commit,
        expected_workflow_sha256=expected_codeql_workflow_sha256,
    )
    _require(ci["run_id"] != codeql["run_id"], "CI and CodeQL run ids collide")
    _validate_constant_time_jobs(ci["jobs"])
    _validate_codeql_jobs(codeql["jobs"])
    return gate
