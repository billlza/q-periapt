#!/usr/bin/env python3
"""Current ABI2 0.1.4 platform-distribution identity and asset contract.

This module contains only prepublication identity: product/revision names, the
exact asset inventory and media types, the source-security gate schema, and the
typed seven-file release-candidate completion receipt.  It contains no fixed
published hashes or remote release observations: those facts belong to the
separate immutable publication-receipt contract because the current producer
has to exist before they do.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NoReturn


PLATFORM_DISTRIBUTION_SCHEMA_VERSION = 1
PLATFORM_DISTRIBUTION_KIND = "qperiapt.abi2_platform_distribution"
PLATFORM_RELEASE_CANDIDATE_SCHEMA_VERSION = 1
PLATFORM_RELEASE_CANDIDATE_KIND = (
    "qperiapt.abi2_platform_release_candidate_receipt"
)
ANDROID_DEVICE_PROOF_SCHEMA_VERSION = 6
ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION = 2

PRODUCT_VERSION = "0.1.4"
DISTRIBUTION_REVISION = "r1"
RELEASE_TAG = f"abi2-platforms-v{PRODUCT_VERSION}"
RELEASE_URL = f"https://github.com/billlza/q-periapt/releases/tag/{RELEASE_TAG}"

RELEASE_MANIFEST = "PLATFORM_DISTRIBUTION.json"
RELEASE_SUMS = "SHA256SUMS"
CANDIDATE_SUMS = "CANDIDATE_SHA256SUMS"
SOURCE_SECURITY_GATE = "ABI2_SOURCE_SECURITY_GATE.json"
SOURCE_SECURITY_GATE_SCHEMA_VERSION = 2
SOURCE_SECURITY_GATE_KIND = "qperiapt.abi2_source_security_gate"
REPOSITORY = "billlza/q-periapt"
MAIN_REF = "refs/heads/main"
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
CODEQL_ANALYSIS_KEY = ".github/workflows/codeql.yml:analyze"
CODEQL_TOOL_VERSION = "2.26.2"
CODEQL_ANALYSIS_CONTRACT = tuple(
    (language, f"/language:{language}")
    for language, _job_name in CODEQL_JOB_CONTRACT
)
MAX_CODEQL_RULE_COUNT = (1 << 31) - 1
MAX_CODEQL_RESULT_COUNT = 100_000

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
# Canonical local-candidate, GitHub-release, and release-attestation order.  The
# mapping is immutable so every producer and consumer shares one content-type
# policy instead of growing a second publication-only authority.  Values match
# GitHub CLI's upload contract: .tar.gz has its explicit application/x-gtar
# branch and an otherwise-unknown .aar falls back to application/octet-stream.
PUBLIC_ASSET_NAMES = tuple(sorted(PLATFORM_RELEASE_FILES))
PUBLIC_ASSET_CONTENT_TYPES: Mapping[str, str] = MappingProxyType(
    {
        RELEASE_MANIFEST: "application/json",
        RELEASE_SUMS: "application/octet-stream",
        ANDROID_RUNTIME_BUNDLE: "application/zip",
        ANDROID_MANIFEST: "application/json",
        ANDROID_AAR: "application/octet-stream",
        LINUX_AARCH64: "application/x-gtar",
        LINUX_X86_64: "application/x-gtar",
    }
)
MAX_PLATFORM_ASSET_BYTES = 512 * 1024 * 1024


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


def _validate_release_candidate_source(value: object) -> dict[str, Any]:
    source = _object(value, "platform release candidate source")
    _exact_keys(
        source,
        frozenset(
            {
                "canonical_source_tree_sha256",
                "git_commit",
                "git_dirty",
                "git_tree",
                "source_date_epoch",
            }
        ),
        "platform release candidate source",
    )
    _sha1(source["git_commit"], "platform release candidate commit")
    _sha1(source["git_tree"], "platform release candidate tree")
    _sha256(
        source["canonical_source_tree_sha256"],
        "platform release candidate canonical source tree",
    )
    _positive_integer(
        source["source_date_epoch"],
        maximum=0xFFFFFFFF,
        label="platform release candidate source epoch",
    )
    _require(
        source["git_dirty"] is False,
        "platform release candidate must be clean-source bound",
    )
    return source


def _validate_release_candidate_assets(
    value: object,
) -> dict[str, dict[str, object]]:
    _require(
        isinstance(value, list),
        "platform release candidate assets must be a list",
    )
    _require(
        len(value) == len(PUBLIC_ASSET_NAMES),
        "platform release candidate asset count differs",
    )
    assets: dict[str, dict[str, object]] = {}
    for index, expected_name in enumerate(PUBLIC_ASSET_NAMES):
        label = f"platform release candidate asset {index}"
        asset = _object(value[index], label)
        _exact_keys(
            asset,
            frozenset({"bytes", "content_type", "name", "sha256"}),
            label,
        )
        _require(asset["name"] == expected_name, f"{label} order/name differs")
        size = _positive_integer(
            asset["bytes"],
            maximum=MAX_PLATFORM_ASSET_BYTES,
            label=f"{label} bytes",
        )
        digest = _sha256(asset["sha256"], f"{label} digest")
        content_type = asset["content_type"]
        _require(
            content_type == PUBLIC_ASSET_CONTENT_TYPES[expected_name],
            f"{label} content type differs",
        )
        assets[expected_name] = {
            "bytes": size,
            "content_type": content_type,
            "name": expected_name,
            "sha256": digest,
        }
    return assets


def _validate_release_candidate_runtime(
    value: object,
    *,
    assets: dict[str, dict[str, object]],
) -> None:
    runtime = _object(value, "platform release candidate Android runtime evidence")
    _exact_keys(
        runtime,
        frozenset(
            {
                "bundle_manifest_sha256",
                "bundle_schema",
                "bundle_sha256",
                "device_abi",
                "device_kind",
                "device_sdk",
                "page_size",
                "proof_schema",
                "proof_sha256",
                "release_mode",
                "tested_aar_manifest_sha256",
                "tested_aar_sha256",
            }
        ),
        "platform release candidate Android runtime evidence",
    )
    _require(
        type(runtime["bundle_schema"]) is int
        and runtime["bundle_schema"] == ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION,
        "platform release candidate Android runtime bundle schema differs",
    )
    _require(
        type(runtime["proof_schema"]) is int
        and runtime["proof_schema"] == ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "platform release candidate Android runtime proof schema differs",
    )
    _require(
        runtime["device_kind"] == "emulator"
        and runtime["device_abi"] == "arm64-v8a"
        and type(runtime["device_sdk"]) is int
        and runtime["device_sdk"] == 35
        and type(runtime["page_size"]) is int
        and runtime["page_size"] == 16_384
        and runtime["release_mode"] is True,
        "platform release candidate Android runtime device boundary differs",
    )
    bundle_sha256 = _sha256(
        runtime["bundle_sha256"],
        "platform release candidate Android runtime bundle",
    )
    tested_aar_sha256 = _sha256(
        runtime["tested_aar_sha256"],
        "platform release candidate Android tested AAR",
    )
    tested_manifest_sha256 = _sha256(
        runtime["tested_aar_manifest_sha256"],
        "platform release candidate Android tested AAR manifest",
    )
    _sha256(
        runtime["bundle_manifest_sha256"],
        "platform release candidate Android runtime bundle manifest",
    )
    _sha256(
        runtime["proof_sha256"],
        "platform release candidate Android runtime proof",
    )
    _require(
        bundle_sha256 == assets[ANDROID_RUNTIME_BUNDLE]["sha256"],
        "platform release candidate Android bundle asset differs",
    )
    _require(
        tested_aar_sha256 == assets[ANDROID_AAR]["sha256"],
        "platform release candidate Android tested AAR differs",
    )
    _require(
        tested_manifest_sha256 == assets[ANDROID_MANIFEST]["sha256"],
        "platform release candidate Android tested manifest differs",
    )


def validate_release_candidate_receipt(value: object) -> dict[str, Any]:
    """Validate one exact prepublication seven-asset completion receipt."""

    receipt = _object(value, "platform release candidate receipt")
    _exact_keys(
        receipt,
        frozenset(
            {
                "android_runtime_evidence",
                "assets",
                "checksums_sha256",
                "kind",
                "platform_distribution_sha256",
                "schema_version",
                "source",
            }
        ),
        "platform release candidate receipt",
    )
    _require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == PLATFORM_RELEASE_CANDIDATE_SCHEMA_VERSION,
        "platform release candidate receipt schema differs",
    )
    _require(
        receipt["kind"] == PLATFORM_RELEASE_CANDIDATE_KIND,
        "platform release candidate receipt kind differs",
    )
    _validate_release_candidate_source(receipt["source"])
    validate_release_candidate_projection(
        {
            "android_runtime_evidence": receipt["android_runtime_evidence"],
            "assets": receipt["assets"],
            "checksums_sha256": receipt["checksums_sha256"],
            "platform_distribution_sha256": receipt[
                "platform_distribution_sha256"
            ],
        }
    )
    return receipt


def validate_release_candidate_projection(value: object) -> dict[str, Any]:
    """Validate the exact receipt fields retained in publication observations."""

    candidate = _object(value, "platform release candidate projection")
    _exact_keys(
        candidate,
        frozenset(
            {
                "android_runtime_evidence",
                "assets",
                "checksums_sha256",
                "platform_distribution_sha256",
            }
        ),
        "platform release candidate projection",
    )
    assets = _validate_release_candidate_assets(candidate["assets"])
    distribution_sha256 = _sha256(
        candidate["platform_distribution_sha256"],
        "platform release candidate distribution manifest",
    )
    checksums_sha256 = _sha256(
        candidate["checksums_sha256"],
        "platform release candidate checksums",
    )
    _require(
        distribution_sha256 == assets[RELEASE_MANIFEST]["sha256"],
        "platform release candidate distribution manifest asset differs",
    )
    _require(
        checksums_sha256 == assets[RELEASE_SUMS]["sha256"],
        "platform release candidate checksums asset differs",
    )
    _validate_release_candidate_runtime(
        candidate["android_runtime_evidence"],
        assets=assets,
    )
    return candidate


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


def _validate_code_scanning(value: object, *, expected_tag_commit: str) -> None:
    code_scanning = _object(value, "source security gate code scanning")
    _exact_keys(
        code_scanning,
        frozenset({"analyses", "main_ref", "open_alerts"}),
        "source security gate code scanning",
    )
    main_ref = _object(code_scanning["main_ref"], "Code Scanning main ref")
    _exact_keys(
        main_ref,
        frozenset({"commit_sha", "ref"}),
        "Code Scanning main ref",
    )
    _require(
        main_ref == {"commit_sha": expected_tag_commit, "ref": MAIN_REF},
        "Code Scanning main ref is not exact R",
    )
    analyses = code_scanning["analyses"]
    _require(isinstance(analyses, list), "Code Scanning analyses must be a list")
    _require(
        len(analyses) == len(CODEQL_ANALYSIS_CONTRACT),
        "Code Scanning analysis count differs",
    )
    analysis_ids: set[int] = set()
    tool_versions: set[str] = set()
    for index, (raw, expected) in enumerate(
        zip(analyses, CODEQL_ANALYSIS_CONTRACT, strict=True)
    ):
        language, category = expected
        label = f"Code Scanning analysis {index}"
        analysis = _object(raw, label)
        _exact_keys(
            analysis,
            frozenset(
                {
                    "analysis_id",
                    "analysis_key",
                    "category",
                    "commit_sha",
                    "error",
                    "ref",
                    "results_count",
                    "rules_count",
                    "tool",
                    "warning",
                }
            ),
            label,
        )
        analysis_id = _positive_integer(
            analysis["analysis_id"],
            maximum=MAX_WORKFLOW_RUN_ID,
            label=f"{label} id",
        )
        _require(
            analysis_id not in analysis_ids,
            "Code Scanning analysis ids are not unique",
        )
        analysis_ids.add(analysis_id)
        _require(
            analysis["analysis_key"] == CODEQL_ANALYSIS_KEY
            and analysis["category"] == category
            and analysis["commit_sha"] == expected_tag_commit
            and analysis["error"] == ""
            and analysis["ref"] == MAIN_REF
            and type(analysis["results_count"]) is int
            and 0 <= analysis["results_count"] <= MAX_CODEQL_RESULT_COUNT
            and analysis["warning"] == "",
            f"{label} ({language}) identity or result differs",
        )
        _positive_integer(
            analysis["rules_count"],
            maximum=MAX_CODEQL_RULE_COUNT,
            label=f"{label} rules count",
        )
        tool = _object(analysis["tool"], f"{label} tool")
        _exact_keys(tool, frozenset({"name", "version"}), f"{label} tool")
        version = tool.get("version")
        _require(
            tool.get("name") == "CodeQL"
            and version == CODEQL_TOOL_VERSION,
            f"{label} tool identity differs",
        )
        tool_versions.add(version)
    _require(
        len(tool_versions) == 1,
        "Code Scanning analyses do not share one CodeQL version",
    )
    _require(
        isinstance(code_scanning["open_alerts"], list)
        and not code_scanning["open_alerts"],
        "Code Scanning main open alerts are not empty",
    )


def validate_source_security_gate(
    value: object,
    *,
    expected_tag_commit: str | None = None,
    expected_source_parent_commit: str | None = None,
    expected_ci_workflow_sha256: str | None = None,
    expected_codeql_workflow_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate exact-R CI, CodeQL workflow, and Code Scanning authority."""

    gate = _object(value, "source security gate")
    _exact_keys(
        gate,
        frozenset(
            {
                "code_scanning",
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
    _validate_code_scanning(
        gate["code_scanning"],
        expected_tag_commit=tag_commit,
    )
    return gate
