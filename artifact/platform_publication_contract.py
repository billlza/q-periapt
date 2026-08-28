#!/usr/bin/env python3
"""Versioned ABI2 platform publication-receipt dispatcher."""

from __future__ import annotations

import platform_stable_publication_contract as stable_contract
import platform_release_contract as historical_r2_contract


PLATFORM_R2_PUBLICATION_KEY = (
    historical_r2_contract.PLATFORM_RELEASE_RECEIPT_KEY
)
# The 0.1.3 line published, so this dispatcher owns the frozen receipt key
# directly instead of importing it from the active candidate contract; the
# 0.1.4 opening renames the candidate contract's family to v0_1_4 while
# this key stays frozen history.
PLATFORM_V0_1_3_PUBLICATION_KEY = "platform_v0_1_3"
PLATFORM_PUBLICATION_KEYS = frozenset(
    {PLATFORM_R2_PUBLICATION_KEY, PLATFORM_V0_1_3_PUBLICATION_KEY}
)


class PlatformPublicationContractError(ValueError):
    """A versioned platform publication receipt violates its contract."""


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        raise PlatformPublicationContractError(
            f"{label} must be a JSON object with string keys"
        )
    return value


def frozen_platform_v0_1_3_receipt() -> dict[str, object]:
    """Return the exact published 0.1.3 platform publication receipt."""

    return {
        "boundary": (
            "Frozen ABI 2 0.1.3 stable platform publication receipt. The pending "
            "state binds the annotated tag, exact source identity, the final "
            "seven-asset local release candidate, and one verified four-product "
            "candidate attestation covering exact-R binary-CT and six-language "
            "CodeQL runs with their actual analysis result counts, plus an empty "
            "main-ref open-alert observation establishing zero unadjudicated "
            "findings; absent remote fields are unrecorded, not evidence of "
            "non-publication. The verified state additionally binds the exact seven "
            "public immutable GitHub release assets, release attestation, fresh "
            "redownload and deep verification, API 35 arm64-v8a 16 KiB emulator "
            "runtime evidence and unpublished external registries. Windows is "
            "excluded from the formal stable asset set until a signed publication "
            "boundary exists. It does not claim registry or store publication, "
            "Windows support, physical-device coverage, or anonymous download "
            "availability; the GitHub CLI observation uses the source-pinned "
            "executable, exactly one bounded credential, a minimal environment, and "
            "empty private configuration. Dynamic digests provide Level-1 "
            "accidental-mismatch detection within repository-trusted evidence; they "
            "do not attest a hostile builder or host."
        ),
        "identity": {
            "distribution_revision": "r1",
            "product_version": "0.1.3",
            "release_tag": "abi2-platforms-v0.1.3",
            "release_url": (
                "https://github.com/billlza/q-periapt/releases/tag/"
                "abi2-platforms-v0.1.3"
            ),
        },
        "kind": "qperiapt.abi2_platform_publication_receipt",
        "observation": {
            "android_runtime_evidence": {
                "bundle_manifest_sha256": (
                    "de06ed8e6d5af5490911a1b15efd3c442a351af89c75115f1dbe2ed949daa699"
                ),
                "bundle_schema": 2,
                "bundle_sha256": (
                    "b669c1400f2897b5dbbc4f8bf15a1af6e791583285effe9dc636f8c9744c40aa"
                ),
                "device_abi": "arm64-v8a",
                "device_kind": "emulator",
                "device_sdk": 35,
                "page_size": 16384,
                "proof_schema": 6,
                "proof_sha256": (
                    "2ca1e093003b2ba7285b138e94f770a0402ad7abe974d03c2428effc7a7557ed"
                ),
                "release_mode": True,
                "tested_aar_manifest_sha256": (
                    "c61bf498ba434c19e756c132d02571d7161d8844544f556584cb1742bfe8ccb6"
                ),
                "tested_aar_sha256": (
                    "b65f1105e513b7c0d6d2d832e712efc58a0bfe4361610454e239f15d37d1b93e"
                ),
            },
            "assembly_receipt_sha256": (
                "4710d26a48f3b064e6547a53d5579046b9ff57af436556b903de3eb539bbc50e"
            ),
            "assets": [
                {
                    "bytes": 3929,
                    "name": "PLATFORM_DISTRIBUTION.json",
                    "sha256": (
                        "20bc095563e76201bfded3c312734cbe1190044ebbaa8f095a9adbd9e219ad4f"
                    ),
                },
                {
                    "bytes": 649,
                    "name": "SHA256SUMS",
                    "sha256": (
                        "5760badf5d25affed157aa135a8a451f1458e81008af26e0829001f2a797c37e"
                    ),
                },
                {
                    "bytes": 3_071_661,
                    "name": "q-periapt-android-0.1.3-16k-runtime-evidence.zip",
                    "sha256": (
                        "b669c1400f2897b5dbbc4f8bf15a1af6e791583285effe9dc636f8c9744c40aa"
                    ),
                },
                {
                    "bytes": 3918,
                    "name": "q-periapt-android-0.1.3-MANIFEST.json",
                    "sha256": (
                        "c61bf498ba434c19e756c132d02571d7161d8844544f556584cb1742bfe8ccb6"
                    ),
                },
                {
                    "bytes": 3_523_107,
                    "name": "q-periapt-android-0.1.3.aar",
                    "sha256": (
                        "b65f1105e513b7c0d6d2d832e712efc58a0bfe4361610454e239f15d37d1b93e"
                    ),
                },
                {
                    "bytes": 1_374_742,
                    "name": "q-periapt-c-abi2-0.1.3-aarch64-unknown-linux-gnu.tar.gz",
                    "sha256": (
                        "ef9a55683599d4c5c709e247e416832e2a4e3a64b642bba6c5b3aec8f9b919ea"
                    ),
                },
                {
                    "bytes": 1_412_929,
                    "name": "q-periapt-c-abi2-0.1.3-x86_64-unknown-linux-gnu.tar.gz",
                    "sha256": (
                        "f128443c316f6bce3a8abafe1e11276a271d0ee7684c794fe5f94297f62a0caf"
                    ),
                },
            ],
            "candidate_attestation": {
                "certificate_san": (
                    "https://github.com/billlza/q-periapt/.github/workflows/"
                    "abi2-platform-candidate.yml@refs/tags/"
                    "abi2-platforms-v0.1.3"
                ),
                "predicate_type": "https://slsa.dev/provenance/v1",
                "security_gate": {
                    "code_scanning": {
                        "analyses": [
                            {
                                "analysis_id": 1_668_257_168,
                                "analysis_key": ".github/workflows/codeql.yml:analyze",
                                "category": "/language:actions",
                                "commit_sha": (
                                    "69e64078ea464109d7e846619e2ce493aa26934f"
                                ),
                                "error": "",
                                "ref": "refs/heads/main",
                                "results_count": 0,
                                "rules_count": 23,
                                "tool": {
                                    "name": "CodeQL",
                                    "version": "2.26.2",
                                },
                                "warning": "",
                            },
                            {
                                "analysis_id": 1_668_259_102,
                                "analysis_key": ".github/workflows/codeql.yml:analyze",
                                "category": "/language:c-cpp",
                                "commit_sha": (
                                    "69e64078ea464109d7e846619e2ce493aa26934f"
                                ),
                                "error": "",
                                "ref": "refs/heads/main",
                                "results_count": 0,
                                "rules_count": 95,
                                "tool": {
                                    "name": "CodeQL",
                                    "version": "2.26.2",
                                },
                                "warning": "",
                            },
                            {
                                "analysis_id": 1_668_263_627,
                                "analysis_key": ".github/workflows/codeql.yml:analyze",
                                "category": "/language:java-kotlin",
                                "commit_sha": (
                                    "69e64078ea464109d7e846619e2ce493aa26934f"
                                ),
                                "error": "",
                                "ref": "refs/heads/main",
                                "results_count": 0,
                                "rules_count": 120,
                                "tool": {
                                    "name": "CodeQL",
                                    "version": "2.26.2",
                                },
                                "warning": "",
                            },
                            {
                                "analysis_id": 1_668_263_802,
                                "analysis_key": ".github/workflows/codeql.yml:analyze",
                                "category": "/language:python",
                                "commit_sha": (
                                    "69e64078ea464109d7e846619e2ce493aa26934f"
                                ),
                                "error": "",
                                "ref": "refs/heads/main",
                                "results_count": 185,
                                "rules_count": 50,
                                "tool": {
                                    "name": "CodeQL",
                                    "version": "2.26.2",
                                },
                                "warning": "",
                            },
                            {
                                "analysis_id": 1_668_295_816,
                                "analysis_key": ".github/workflows/codeql.yml:analyze",
                                "category": "/language:rust",
                                "commit_sha": (
                                    "69e64078ea464109d7e846619e2ce493aa26934f"
                                ),
                                "error": "",
                                "ref": "refs/heads/main",
                                "results_count": 14,
                                "rules_count": 27,
                                "tool": {
                                    "name": "CodeQL",
                                    "version": "2.26.2",
                                },
                                "warning": "",
                            },
                            {
                                "analysis_id": 1_668_376_181,
                                "analysis_key": ".github/workflows/codeql.yml:analyze",
                                "category": "/language:swift",
                                "commit_sha": (
                                    "69e64078ea464109d7e846619e2ce493aa26934f"
                                ),
                                "error": "",
                                "ref": "refs/heads/main",
                                "results_count": 0,
                                "rules_count": 28,
                                "tool": {
                                    "name": "CodeQL",
                                    "version": "2.26.2",
                                },
                                "warning": "",
                            },
                        ],
                        "main_ref": {
                            "commit_sha": "69e64078ea464109d7e846619e2ce493aa26934f",
                            "ref": "refs/heads/main",
                        },
                        "open_alerts": [],
                    },
                    "kind": "qperiapt.abi2_source_security_gate",
                    "observation_tools": {
                        "github_cli": {
                            "name": "gh",
                            "path": "/usr/bin/gh",
                            "sha256": (
                                "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409"
                            ),
                            "version": "gh version 2.97.0 (2026-07-31)",
                        },
                    },
                    "receipt_sha256": (
                        "7148418d914409df142f5fca64a35b500cbf93b3aa306da7407e05955ca5aa0a"
                    ),
                    "repository": "billlza/q-periapt",
                    "schema_version": 2,
                    "source_parent_commit": "e9ae27fcc8b66c37a700cfa0e1efbc4219eb5688",
                    "tag_commit": "69e64078ea464109d7e846619e2ce493aa26934f",
                    "workflows": {
                        "ci": {
                            "conclusion": "success",
                            "event": "push",
                            "head_branch": "main",
                            "head_sha": "69e64078ea464109d7e846619e2ce493aa26934f",
                            "jobs": [
                                {
                                    "architecture": "x86_64",
                                    "conclusion": "success",
                                    "implementation": "portable-c",
                                    "job_id": 97_775_185_081,
                                    "name": "Binary CT [x86_64-portable]",
                                    "status": "completed",
                                },
                                {
                                    "architecture": "aarch64",
                                    "conclusion": "success",
                                    "implementation": "aarch64-native",
                                    "job_id": 97_775_185_082,
                                    "name": "Binary CT [aarch64-native]",
                                    "status": "completed",
                                },
                            ],
                            "run_attempt": 1,
                            "run_id": 32_839_346_738,
                            "status": "completed",
                            "workflow_name": "ci",
                            "workflow_path": ".github/workflows/ci.yml",
                            "workflow_sha256": (
                                "0d5b120cf08af299904d574e6d888cbc9b0c2bfc8c2c8a2025ad62e84e1747bc"
                            ),
                        },
                        "codeql": {
                            "conclusion": "success",
                            "event": "push",
                            "head_branch": "main",
                            "head_sha": "69e64078ea464109d7e846619e2ce493aa26934f",
                            "jobs": [
                                {
                                    "conclusion": "success",
                                    "job_id": 97_775_185_116,
                                    "language": "actions",
                                    "name": "Analyze (actions)",
                                    "status": "completed",
                                },
                                {
                                    "conclusion": "success",
                                    "job_id": 97_775_185_048,
                                    "language": "c-cpp",
                                    "name": "Analyze (c-cpp)",
                                    "status": "completed",
                                },
                                {
                                    "conclusion": "success",
                                    "job_id": 97_775_185_038,
                                    "language": "java-kotlin",
                                    "name": "Analyze (java-kotlin)",
                                    "status": "completed",
                                },
                                {
                                    "conclusion": "success",
                                    "job_id": 97_775_184_838,
                                    "language": "python",
                                    "name": "Analyze (python)",
                                    "status": "completed",
                                },
                                {
                                    "conclusion": "success",
                                    "job_id": 97_775_185_086,
                                    "language": "rust",
                                    "name": "Analyze (rust)",
                                    "status": "completed",
                                },
                                {
                                    "conclusion": "success",
                                    "job_id": 97_775_185_002,
                                    "language": "swift",
                                    "name": "Analyze (swift)",
                                    "status": "completed",
                                },
                            ],
                            "run_attempt": 1,
                            "run_id": 32_839_346_792,
                            "status": "completed",
                            "workflow_name": "CodeQL",
                            "workflow_path": ".github/workflows/codeql.yml",
                            "workflow_sha256": (
                                "3cf881d8731c50d9237eca41dd7d05d6d1af0188e958baa3109ab957802884c5"
                            ),
                        },
                    },
                },
                "signer_workflow": (
                    "https://github.com/billlza/q-periapt/.github/workflows/"
                    "abi2-platform-candidate.yml@refs/tags/"
                    "abi2-platforms-v0.1.3"
                ),
                "source_digest": "69e64078ea464109d7e846619e2ce493aa26934f",
                "source_ref": "refs/tags/abi2-platforms-v0.1.3",
                "subjects": [
                    {
                        "digest": {
                            "sha256": (
                                "b65f1105e513b7c0d6d2d832e712efc58a0bfe4361610454e239f15d37d1b93e"
                            ),
                        },
                        "name": "q-periapt-android-0.1.3.aar",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "c61bf498ba434c19e756c132d02571d7161d8844544f556584cb1742bfe8ccb6"
                            ),
                        },
                        "name": "q-periapt-android-0.1.3-MANIFEST.json",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "f128443c316f6bce3a8abafe1e11276a271d0ee7684c794fe5f94297f62a0caf"
                            ),
                        },
                        "name": (
                            "q-periapt-c-abi2-0.1.3-x86_64-unknown-linux-gnu.tar.gz"
                        ),
                    },
                    {
                        "digest": {
                            "sha256": (
                                "ef9a55683599d4c5c709e247e416832e2a4e3a64b642bba6c5b3aec8f9b919ea"
                            ),
                        },
                        "name": (
                            "q-periapt-c-abi2-0.1.3-aarch64-unknown-linux-gnu.tar.gz"
                        ),
                    },
                    {
                        "digest": {
                            "sha256": (
                                "bfbd72070ba3e3b27593be66eeb0083b957065bc7bbc44541298eb10a5e5e502"
                            ),
                        },
                        "name": "CANDIDATE_SHA256SUMS",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "7148418d914409df142f5fca64a35b500cbf93b3aa306da7407e05955ca5aa0a"
                            ),
                        },
                        "name": "ABI2_SOURCE_SECURITY_GATE.json",
                    },
                ],
                "verification_record_sha256": (
                    "b33df5e49a318fcf3cf635449689843b6ad325290968ab402ad86bc1d4c27ccc"
                ),
                "verified": True,
                "verified_at": "2026-08-25T11:28:06Z",
                "workflow_run_attempt": 1,
                "workflow_run_id": 32_841_904_542,
            },
            "checksums_sha256": (
                "5760badf5d25affed157aa135a8a451f1458e81008af26e0829001f2a797c37e"
            ),
            "draft": False,
            "fresh_download_verification": {
                "asset_count": 7,
                "deep_distribution_verified": True,
                "record_sha256": (
                    "cfda091d510df8bf9b26d3322d649e7b6b4737b8b85155d97000ecef98e98d0f"
                ),
                "verified_at": "2026-08-25T19:23:46Z",
                "verifier_commit": "69e64078ea464109d7e846619e2ce493aa26934f",
            },
            "immutable_release": True,
            "observed_at": "2026-08-25T19:23:51Z",
            "platform_distribution_sha256": (
                "20bc095563e76201bfded3c312734cbe1190044ebbaa8f095a9adbd9e219ad4f"
            ),
            "prerelease": False,
            "public_release": True,
            "published_at": "2026-08-25T17:28:59Z",
            "registries": {
                "crates_io": "not_published",
                "deb": "not_published",
                "maven_central": "not_published",
                "msix": "not_published",
                "rpm": "not_published",
            },
            "release_asset_verification_count": 7,
            "release_attestation": {
                "certificate_san": "https://dotcom.releases.github.com",
                "predicate_type": "https://in-toto.io/attestation/release/v0.2",
                "subjects": [
                    {
                        "digest": {
                            "sha1": "38b84eb5e174021f0ee59ef8b13b2aef6d656f37",
                        },
                        "uri": "pkg:github/billlza/q-periapt@abi2-platforms-v0.1.3",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "20bc095563e76201bfded3c312734cbe1190044ebbaa8f095a9adbd9e219ad4f"
                            ),
                        },
                        "name": "PLATFORM_DISTRIBUTION.json",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "5760badf5d25affed157aa135a8a451f1458e81008af26e0829001f2a797c37e"
                            ),
                        },
                        "name": "SHA256SUMS",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "b669c1400f2897b5dbbc4f8bf15a1af6e791583285effe9dc636f8c9744c40aa"
                            ),
                        },
                        "name": "q-periapt-android-0.1.3-16k-runtime-evidence.zip",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "c61bf498ba434c19e756c132d02571d7161d8844544f556584cb1742bfe8ccb6"
                            ),
                        },
                        "name": "q-periapt-android-0.1.3-MANIFEST.json",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "b65f1105e513b7c0d6d2d832e712efc58a0bfe4361610454e239f15d37d1b93e"
                            ),
                        },
                        "name": "q-periapt-android-0.1.3.aar",
                    },
                    {
                        "digest": {
                            "sha256": (
                                "ef9a55683599d4c5c709e247e416832e2a4e3a64b642bba6c5b3aec8f9b919ea"
                            ),
                        },
                        "name": (
                            "q-periapt-c-abi2-0.1.3-aarch64-unknown-linux-gnu.tar.gz"
                        ),
                    },
                    {
                        "digest": {
                            "sha256": (
                                "f128443c316f6bce3a8abafe1e11276a271d0ee7684c794fe5f94297f62a0caf"
                            ),
                        },
                        "name": (
                            "q-periapt-c-abi2-0.1.3-x86_64-unknown-linux-gnu.tar.gz"
                        ),
                    },
                ],
                "verification_record_sha256": (
                    "5972c5741b6609a10ab8bd58b4ba3b61be820f66c137805211a1ab643234d41b"
                ),
                "verified": True,
            },
            "release_candidate": {
                "android_runtime_evidence": {
                    "bundle_manifest_sha256": (
                        "de06ed8e6d5af5490911a1b15efd3c442a351af89c75115f1dbe2ed949daa699"
                    ),
                    "bundle_schema": 2,
                    "bundle_sha256": (
                        "b669c1400f2897b5dbbc4f8bf15a1af6e791583285effe9dc636f8c9744c40aa"
                    ),
                    "device_abi": "arm64-v8a",
                    "device_kind": "emulator",
                    "device_sdk": 35,
                    "page_size": 16384,
                    "proof_schema": 6,
                    "proof_sha256": (
                        "2ca1e093003b2ba7285b138e94f770a0402ad7abe974d03c2428effc7a7557ed"
                    ),
                    "release_mode": True,
                    "tested_aar_manifest_sha256": (
                        "c61bf498ba434c19e756c132d02571d7161d8844544f556584cb1742bfe8ccb6"
                    ),
                    "tested_aar_sha256": (
                        "b65f1105e513b7c0d6d2d832e712efc58a0bfe4361610454e239f15d37d1b93e"
                    ),
                },
                "assets": [
                    {
                        "bytes": 3929,
                        "content_type": "application/json",
                        "name": "PLATFORM_DISTRIBUTION.json",
                        "sha256": (
                            "20bc095563e76201bfded3c312734cbe1190044ebbaa8f095a9adbd9e219ad4f"
                        ),
                    },
                    {
                        "bytes": 649,
                        "content_type": "application/octet-stream",
                        "name": "SHA256SUMS",
                        "sha256": (
                            "5760badf5d25affed157aa135a8a451f1458e81008af26e0829001f2a797c37e"
                        ),
                    },
                    {
                        "bytes": 3_071_661,
                        "content_type": "application/zip",
                        "name": "q-periapt-android-0.1.3-16k-runtime-evidence.zip",
                        "sha256": (
                            "b669c1400f2897b5dbbc4f8bf15a1af6e791583285effe9dc636f8c9744c40aa"
                        ),
                    },
                    {
                        "bytes": 3918,
                        "content_type": "application/json",
                        "name": "q-periapt-android-0.1.3-MANIFEST.json",
                        "sha256": (
                            "c61bf498ba434c19e756c132d02571d7161d8844544f556584cb1742bfe8ccb6"
                        ),
                    },
                    {
                        "bytes": 3_523_107,
                        "content_type": "application/octet-stream",
                        "name": "q-periapt-android-0.1.3.aar",
                        "sha256": (
                            "b65f1105e513b7c0d6d2d832e712efc58a0bfe4361610454e239f15d37d1b93e"
                        ),
                    },
                    {
                        "bytes": 1_374_742,
                        "content_type": "application/x-gtar",
                        "name": (
                            "q-periapt-c-abi2-0.1.3-aarch64-unknown-linux-gnu.tar.gz"
                        ),
                        "sha256": (
                            "ef9a55683599d4c5c709e247e416832e2a4e3a64b642bba6c5b3aec8f9b919ea"
                        ),
                    },
                    {
                        "bytes": 1_412_929,
                        "content_type": "application/x-gtar",
                        "name": (
                            "q-periapt-c-abi2-0.1.3-x86_64-unknown-linux-gnu.tar.gz"
                        ),
                        "sha256": (
                            "f128443c316f6bce3a8abafe1e11276a271d0ee7684c794fe5f94297f62a0caf"
                        ),
                    },
                ],
                "checksums_sha256": (
                    "5760badf5d25affed157aa135a8a451f1458e81008af26e0829001f2a797c37e"
                ),
                "platform_distribution_sha256": (
                    "20bc095563e76201bfded3c312734cbe1190044ebbaa8f095a9adbd9e219ad4f"
                ),
            },
            "release_id": 376_421_150,
            "source": {
                "canonical_source_tree_sha256": (
                    "2a2f0961c9a6fd3e5f410d78f760365593876b5036ddcaf491e917a6bb47e8db"
                ),
                "source_date_epoch": 1_787_655_106,
                "source_parent_commit": "e9ae27fcc8b66c37a700cfa0e1efbc4219eb5688",
                "tag_commit": "69e64078ea464109d7e846619e2ce493aa26934f",
                "tag_object": "38b84eb5e174021f0ee59ef8b13b2aef6d656f37",
                "tag_tree": "4c05594b8f8d305c8a22dc8a25b87685856854c5",
                "verifier_commit": "69e64078ea464109d7e846619e2ce493aa26934f",
            },
        },
        "schema_version": 3,
        "status": "observed_public_immutable_fresh_download_verified",
    }


def validate_release_publications(manifest: dict[str, object]) -> None:
    """Dispatch exact versioned receipt leaves without weakening either one."""

    if not isinstance(manifest, dict):
        raise PlatformPublicationContractError(
            "results manifest must be a JSON object"
        )
    publications_value = manifest.get("release_publications")
    if publications_value is None:
        return
    publications = _object(publications_value, "release_publications")
    unknown = sorted(set(publications) - PLATFORM_PUBLICATION_KEYS)
    if unknown:
        raise PlatformPublicationContractError(
            f"release_publications has unknown entries: {unknown!r}"
        )

    if PLATFORM_R2_PUBLICATION_KEY in publications:
        historical_receipt = _object(
            publications[PLATFORM_R2_PUBLICATION_KEY],
            "platform r2 publication receipt",
        )
        if not isinstance(historical_receipt.get("status"), str):
            raise PlatformPublicationContractError(
                "platform r2 publication status must be a string"
            )
        try:
            historical_r2_contract.validate_release_publications(
                {
                    "release_publications": {
                        PLATFORM_R2_PUBLICATION_KEY: historical_receipt
                    }
                }
            )
        except historical_r2_contract.PlatformReleaseContractError as exc:
            raise PlatformPublicationContractError(str(exc)) from exc

    if PLATFORM_V0_1_3_PUBLICATION_KEY in publications:
        stable_leaf = publications[PLATFORM_V0_1_3_PUBLICATION_KEY]
        if _json_deep_equal(stable_leaf, frozen_platform_v0_1_3_receipt()):
            # The 0.1.3 line published: deep equality with the frozen
            # verified receipt is the entire frozen-history contract, and
            # that receipt passed the full structural validation below
            # when it was committed.
            return
        # The structural candidate-contract machinery below stays the
        # active path for receipts that are not the frozen publication
        # until the 0.1.4 opening renames it to the platform_v0_1_4
        # family; the frozen branch above then becomes this key's only
        # accepting path.
        try:
            stable_contract.validate_v0_1_3_publication_receipt(stable_leaf)
        except stable_contract.PlatformV013PublicationContractError as exc:
            raise PlatformPublicationContractError(str(exc)) from exc


def _publication_entries(
    manifest: dict[str, object],
) -> dict[str, object]:
    publications = manifest.get("release_publications")
    if publications is None:
        return {}
    return _object(publications, "release_publications")


def _json_deep_equal(left: object, right: object) -> bool:
    """Compare already-validated JSON values without Python bool/int aliasing."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_deep_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_deep_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _require_unchanged_publication(
    previous: dict[str, object],
    current: dict[str, object],
    key: str,
) -> None:
    if key not in previous:
        return
    if key not in current:
        raise PlatformPublicationContractError(
            f"release publication {key!r} cannot be removed"
        )
    if not _json_deep_equal(previous[key], current[key]):
        raise PlatformPublicationContractError(
            f"release publication {key!r} cannot change once recorded"
        )


def validate_release_publication_transition(
    previous: dict[str, object], current: dict[str, object]
) -> None:
    """Validate the monotonic first-parent transition between two manifests.

    This function is intentionally pure: it validates both inputs before
    comparing them and never normalizes or mutates either manifest.
    """

    validate_release_publications(previous)
    validate_release_publications(current)
    previous_publications = _publication_entries(previous)
    current_publications = _publication_entries(current)

    if (
        PLATFORM_R2_PUBLICATION_KEY not in previous_publications
        and PLATFORM_R2_PUBLICATION_KEY in current_publications
    ):
        raise PlatformPublicationContractError(
            "historical platform r2 publication cannot be introduced by a future transition"
        )

    _require_unchanged_publication(
        previous_publications,
        current_publications,
        PLATFORM_R2_PUBLICATION_KEY,
    )

    frozen_stable = frozen_platform_v0_1_3_receipt()
    if (
        PLATFORM_V0_1_3_PUBLICATION_KEY not in previous_publications
        and PLATFORM_V0_1_3_PUBLICATION_KEY in current_publications
        and _json_deep_equal(
            current_publications[PLATFORM_V0_1_3_PUBLICATION_KEY],
            frozen_stable,
        )
    ):
        raise PlatformPublicationContractError(
            "frozen platform 0.1.3 publication cannot be introduced by a "
            "future transition"
        )
    if PLATFORM_V0_1_3_PUBLICATION_KEY in previous_publications and (
        _json_deep_equal(
            previous_publications[PLATFORM_V0_1_3_PUBLICATION_KEY],
            frozen_stable,
        )
    ):
        _require_unchanged_publication(
            previous_publications,
            current_publications,
            PLATFORM_V0_1_3_PUBLICATION_KEY,
        )
        return

    # The pending/promotion machinery below stays in place for receipts
    # that are not the frozen publication until the 0.1.4 opening renames
    # it to the platform_v0_1_4 family; the frozen rules above then become
    # this key's only transition contract.
    if PLATFORM_V0_1_3_PUBLICATION_KEY not in previous_publications:
        if PLATFORM_V0_1_3_PUBLICATION_KEY in current_publications:
            current_stable = _object(
                current_publications[PLATFORM_V0_1_3_PUBLICATION_KEY],
                "new platform 0.1.3 publication receipt",
            )
            if (
                current_stable["status"]
                != stable_contract.PLATFORM_V0_1_3_STATUS_PENDING
            ):
                raise PlatformPublicationContractError(
                    "platform 0.1.3 publication must first be recorded as pending"
                )
        return
    if PLATFORM_V0_1_3_PUBLICATION_KEY not in current_publications:
        raise PlatformPublicationContractError(
            "release publication 'platform_v0_1_3' cannot be removed"
        )

    previous_stable = _object(
        previous_publications[PLATFORM_V0_1_3_PUBLICATION_KEY],
        "previous platform 0.1.3 publication receipt",
    )
    current_stable = _object(
        current_publications[PLATFORM_V0_1_3_PUBLICATION_KEY],
        "current platform 0.1.3 publication receipt",
    )
    previous_status = previous_stable["status"]
    current_status = current_stable["status"]

    if previous_status == stable_contract.PLATFORM_V0_1_3_STATUS_VERIFIED:
        if not _json_deep_equal(previous_stable, current_stable):
            raise PlatformPublicationContractError(
                "verified platform 0.1.3 publication receipt cannot change"
            )
        return

    if current_status == stable_contract.PLATFORM_V0_1_3_STATUS_PENDING:
        if not _json_deep_equal(previous_stable, current_stable):
            raise PlatformPublicationContractError(
                "pending platform 0.1.3 publication receipt may only remain "
                "byte-semantically unchanged or advance to verified"
            )
        return

    # Both leaves were validated above, so this is the only remaining state
    # transition: pending -> verified. The publication timestamp and all new
    # verified-only fields may be learned later, but every already-observed fact
    # must remain identical.
    for field in ("boundary", "identity", "kind", "schema_version"):
        if not _json_deep_equal(previous_stable[field], current_stable[field]):
            raise PlatformPublicationContractError(
                "platform 0.1.3 pending-to-verified transition changed "
                f"the recorded {field}"
            )
    previous_observation = _object(
        previous_stable["observation"],
        "previous platform 0.1.3 observation",
    )
    current_observation = _object(
        current_stable["observation"],
        "current platform 0.1.3 observation",
    )
    for field in ("source", "candidate_attestation", "release_candidate"):
        if not _json_deep_equal(
            previous_observation[field], current_observation[field]
        ):
            raise PlatformPublicationContractError(
                "platform 0.1.3 pending-to-verified transition changed "
                f"the recorded {field} facts"
            )
    previous_observed_at = stable_contract.parse_utc_timestamp(
        previous_observation["observed_at"],
        "previous platform 0.1.3 observed_at",
    )
    current_observed_at = stable_contract.parse_utc_timestamp(
        current_observation["observed_at"],
        "current platform 0.1.3 observed_at",
    )
    if current_observed_at < previous_observed_at:
        raise PlatformPublicationContractError(
            "platform 0.1.3 pending-to-verified observed_at moved backwards"
        )
