#!/usr/bin/env python3
"""Fail-closed tests for the frozen stable publication receipt."""

from __future__ import annotations

import copy
import operator
import unittest

import android_device_proof
import platform_stable_publication_contract as contract
import platform_distribution_contract as current_distribution_contract


def _digest(index: int) -> str:
    return f"{index:064x}"


def _sha256_subject(name: str, digest: str) -> dict[str, object]:
    return {"digest": {"sha256": digest}, "name": name}


def _security_gate_projection(
    tag_commit: str, source_parent_commit: str, receipt_sha256: str
) -> dict[str, object]:
    def workflow(
        *,
        name: str,
        path: str,
        run_id: int,
        jobs: list[dict[str, object]],
        digest: str,
    ) -> dict[str, object]:
        return {
            "conclusion": "success",
            "event": "push",
            "head_branch": "main",
            "head_sha": tag_commit,
            "jobs": jobs,
            "run_attempt": 1,
            "run_id": run_id,
            "status": "completed",
            "workflow_name": name,
            "workflow_path": path,
            "workflow_sha256": digest,
        }

    ct_jobs = [
        {
            "architecture": architecture,
            "conclusion": "success",
            "implementation": implementation,
            "job_id": 100 + index,
            "name": name,
            "status": "completed",
        }
        for index, (architecture, implementation, name) in enumerate(
            current_distribution_contract.CONSTANT_TIME_JOB_CONTRACT
        )
    ]
    codeql_jobs = [
        {
            "conclusion": "success",
            "job_id": 200 + index,
            "language": language,
            "name": name,
            "status": "completed",
        }
        for index, (language, name) in enumerate(
            current_distribution_contract.CODEQL_JOB_CONTRACT
        )
    ]
    code_scanning_analyses = [
        {
            "analysis_id": 300 + index,
            "analysis_key": current_distribution_contract.CODEQL_ANALYSIS_KEY,
            "category": category,
            "commit_sha": tag_commit,
            "error": "",
            "ref": current_distribution_contract.MAIN_REF,
            "results_count": (
                185 if _language == "python" else 14 if _language == "rust" else 0
            ),
            "rules_count": 20 + index,
            "tool": {
                "name": "CodeQL",
                "version": current_distribution_contract.CODEQL_TOOL_VERSION,
            },
            "warning": "",
        }
        for index, (_language, category) in enumerate(
            current_distribution_contract.CODEQL_ANALYSIS_CONTRACT
        )
    ]
    return {
        "code_scanning": {
            "analyses": code_scanning_analyses,
            "main_ref": {
                "commit_sha": tag_commit,
                "ref": current_distribution_contract.MAIN_REF,
            },
            "open_alerts": [],
        },
        "kind": current_distribution_contract.SOURCE_SECURITY_GATE_KIND,
        "observation_tools": {
            "github_cli": {
                "name": "gh",
                "path": "/usr/bin/gh",
                "sha256": _digest(12),
                "version": "gh version 2.94.0 (2026-08-01)",
            }
        },
        "receipt_sha256": receipt_sha256,
        "repository": current_distribution_contract.REPOSITORY,
        "schema_version": (
            current_distribution_contract.SOURCE_SECURITY_GATE_SCHEMA_VERSION
        ),
        "source_parent_commit": source_parent_commit,
        "tag_commit": tag_commit,
        "workflows": {
            "ci": workflow(
                name=current_distribution_contract.CI_WORKFLOW_NAME,
                path=current_distribution_contract.CI_WORKFLOW_PATH,
                run_id=10,
                jobs=ct_jobs,
                digest=_digest(10),
            ),
            "codeql": workflow(
                name=current_distribution_contract.CODEQL_WORKFLOW_NAME,
                path=current_distribution_contract.CODEQL_WORKFLOW_PATH,
                run_id=20,
                jobs=codeql_jobs,
                digest=_digest(11),
            ),
        },
    }


def _release_candidate(
    candidate_digests: dict[str, str],
) -> dict[str, object]:
    asset_digests = {
        name: (
            candidate_digests[name]
            if name in contract.CANDIDATE_PUBLIC_ASSET_NAMES
            else _digest(index)
        )
        for index, name in enumerate(contract.PUBLIC_ASSET_NAMES, start=60)
    }
    return {
        "android_runtime_evidence": {
            "bundle_manifest_sha256": _digest(80),
            "bundle_schema": 2,
            "bundle_sha256": asset_digests[contract.ANDROID_RUNTIME_BUNDLE],
            "device_abi": "arm64-v8a",
            "device_kind": "emulator",
            "device_sdk": 35,
            "page_size": 16_384,
            "proof_schema": 6,
            "proof_sha256": _digest(81),
            "release_mode": True,
            "tested_aar_manifest_sha256": asset_digests[
                contract.ANDROID_MANIFEST
            ],
            "tested_aar_sha256": asset_digests[contract.ANDROID_AAR],
        },
        "assets": [
            {
                "bytes": 1_000 + index,
                "content_type": contract.PUBLIC_ASSET_CONTENT_TYPES[name],
                "name": name,
                "sha256": asset_digests[name],
            }
            for index, name in enumerate(contract.PUBLIC_ASSET_NAMES)
        ],
        "checksums_sha256": asset_digests[contract.RELEASE_SUMS],
        "platform_distribution_sha256": asset_digests[
            contract.RELEASE_MANIFEST
        ],
    }


def pending_receipt() -> dict[str, object]:
    tag_commit = "1" * 40
    source_parent_commit = "4" * 40
    candidate_digests = {
        name: _digest(index)
        for index, name in enumerate(
            contract.CANDIDATE_SUBJECT_NAMES, start=20
        )
    }
    return {
        "boundary": contract.PLATFORM_V0_1_4_PUBLICATION_BOUNDARY,
        "identity": {
            "distribution_revision": contract.DISTRIBUTION_REVISION,
            "product_version": contract.PRODUCT_VERSION,
            "release_tag": contract.RELEASE_TAG,
            "release_url": contract.RELEASE_URL,
        },
        "kind": contract.PLATFORM_V0_1_4_PUBLICATION_KIND,
        "observation": {
            "assembly_receipt_sha256": _digest(39),
            "candidate_attestation": {
                "certificate_san": contract.CANDIDATE_SIGNER_WORKFLOW,
                "predicate_type": contract.CANDIDATE_PREDICATE_TYPE,
                "security_gate": _security_gate_projection(
                    tag_commit,
                    source_parent_commit,
                    candidate_digests[
                        current_distribution_contract.SOURCE_SECURITY_GATE
                    ],
                ),
                "signer_workflow": contract.CANDIDATE_SIGNER_WORKFLOW,
                "source_digest": tag_commit,
                "source_ref": contract.RELEASE_REF,
                "subjects": [
                    _sha256_subject(name, candidate_digests[name])
                    for name in contract.CANDIDATE_SUBJECT_NAMES
                ],
                "verification_record_sha256": _digest(40),
                "verified": True,
                "verified_at": "2026-08-14T01:00:00Z",
                "workflow_run_attempt": 1,
                "workflow_run_id": 31_700_000_001,
            },
            "observed_at": "2026-08-14T04:00:00Z",
            "release_candidate": _release_candidate(candidate_digests),
            "source": {
                "canonical_source_tree_sha256": _digest(41),
                "source_date_epoch": 1_700_000_000,
                "source_parent_commit": source_parent_commit,
                "tag_commit": tag_commit,
                "tag_object": "2" * 40,
                "tag_tree": "3" * 40,
                "verifier_commit": tag_commit,
            },
        },
        "schema_version": contract.PLATFORM_V0_1_4_PUBLICATION_SCHEMA_VERSION,
        "status": contract.PLATFORM_V0_1_4_STATUS_PENDING,
    }


def verified_receipt() -> dict[str, object]:
    receipt = pending_receipt()
    receipt["status"] = contract.PLATFORM_V0_1_4_STATUS_VERIFIED
    observation = receipt["observation"]
    candidate_subjects = {
        subject["name"]: subject["digest"]["sha256"]
        for subject in observation["candidate_attestation"]["subjects"]
    }
    release_candidate = observation["release_candidate"]
    asset_digests = {
        asset["name"]: asset["sha256"]
        for asset in release_candidate["assets"]
    }
    assets = [
        {
            "bytes": asset["bytes"],
            "name": asset["name"],
            "sha256": asset["sha256"],
        }
        for asset in release_candidate["assets"]
    ]
    observation.update(
        {
            "android_runtime_evidence": copy.deepcopy(
                release_candidate["android_runtime_evidence"]
            ),
            "assets": assets,
            "checksums_sha256": asset_digests[contract.RELEASE_SUMS],
            "draft": False,
            "fresh_download_verification": {
                "asset_count": len(contract.PUBLIC_ASSET_NAMES),
                "deep_distribution_verified": True,
                "record_sha256": _digest(82),
                "verified_at": "2026-08-14T03:00:00Z",
                "verifier_commit": observation["source"]["tag_commit"],
            },
            "immutable_release": True,
            "platform_distribution_sha256": asset_digests[
                contract.RELEASE_MANIFEST
            ],
            "prerelease": False,
            "public_release": True,
            "published_at": "2026-08-14T02:00:00Z",
            "registries": dict(contract.REGISTRY_STATES),
            "release_asset_verification_count": len(
                contract.PUBLIC_ASSET_NAMES
            ),
            "release_attestation": {
                "certificate_san": contract.RELEASE_CERTIFICATE_SAN,
                "predicate_type": contract.RELEASE_PREDICATE_TYPE,
                "subjects": [
                    {
                        "digest": {
                            "sha1": observation["source"]["tag_object"]
                        },
                        "uri": contract.TAG_SUBJECT_URI,
                    },
                    *[
                        _sha256_subject(name, asset_digests[name])
                        for name in contract.PUBLIC_ASSET_NAMES
                    ],
                ],
                "verification_record_sha256": _digest(83),
                "verified": True,
            },
            "release_id": 2_345_678,
        }
    )
    return receipt


class PlatformV014PublicationContractTests(unittest.TestCase):
    def validate(self, receipt: object) -> None:
        contract.validate_v0_1_4_publication_receipt(receipt)

    def test_public_utc_parser_is_exact_and_timezone_aware(self) -> None:
        parsed = contract.parse_utc_timestamp(
            "2026-08-14T04:00:00Z", "test timestamp"
        )
        self.assertEqual("2026-08-14T04:00:00+00:00", parsed.isoformat())
        for value in (
            "2026-08-14T04:00:00+00:00",
            "2026-08-14T04:00:00.000Z",
            "2026-08-14 04:00:00Z",
            True,
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    contract.parse_utc_timestamp(value, "test timestamp")

    def test_pending_state_has_only_candidate_safe_exact_fields(self) -> None:
        receipt = pending_receipt()
        self.validate(receipt)
        self.assertEqual(
            set(receipt["observation"]),
            {
                "assembly_receipt_sha256",
                "candidate_attestation",
                "observed_at",
                "release_candidate",
                "source",
            },
        )

        for mutation in ("top-extra", "observation-extra", "candidate-extra"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(receipt)
                if mutation == "top-extra":
                    changed["unexpected"] = None
                elif mutation == "observation-extra":
                    changed["observation"]["public_release"] = False
                else:
                    changed["observation"]["candidate_attestation"][
                        "runner_environment"
                    ] = "github-hosted"
                with self.assertRaisesRegex(
                    contract.PlatformV014PublicationContractError,
                    "keys differ",
                ):
                    self.validate(changed)

    def test_pending_release_candidate_is_exact_and_candidate_crosslinked(self) -> None:
        for mutation in (
            "legacy-schema",
            "asset-order",
            "asset-content-type",
            "candidate-crosslink",
            "runtime-crosslink",
        ):
            with self.subTest(mutation=mutation):
                receipt = pending_receipt()
                if mutation == "legacy-schema":
                    receipt["schema_version"] = 2
                elif mutation == "asset-order":
                    assets = receipt["observation"]["release_candidate"]["assets"]
                    assets[0], assets[1] = assets[1], assets[0]
                elif mutation == "asset-content-type":
                    receipt["observation"]["release_candidate"]["assets"][0][
                        "content_type"
                    ] = "application/octet-stream"
                elif mutation == "candidate-crosslink":
                    name = contract.ANDROID_AAR
                    index = contract.PUBLIC_ASSET_NAMES.index(name)
                    receipt["observation"]["release_candidate"]["assets"][index][
                        "sha256"
                    ] = _digest(150)
                else:
                    receipt["observation"]["release_candidate"][
                        "android_runtime_evidence"
                    ]["bundle_sha256"] = _digest(151)
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_discriminant_and_json_scalar_types_fail_closed(self) -> None:
        mutations = (
            (("status",), "candidate_pending_publication"),
            (("status",), []),
            (("status",), {}),
            (("schema_version",), True),
            (
                (
                    "observation",
                    "candidate_attestation",
                    "workflow_run_id",
                ),
                True,
            ),
            (
                (
                    "observation",
                    "candidate_attestation",
                    "workflow_run_id",
                ),
                contract.MAX_WORKFLOW_RUN_ID + 1,
            ),
            (
                (
                    "observation",
                    "candidate_attestation",
                    "workflow_run_attempt",
                ),
                True,
            ),
            (
                (
                    "observation",
                    "candidate_attestation",
                    "workflow_run_attempt",
                ),
                0,
            ),
            (
                (
                    "observation",
                    "candidate_attestation",
                    "workflow_run_attempt",
                ),
                contract.MAX_WORKFLOW_RUN_ATTEMPT + 1,
            ),
            (
                ("observation", "candidate_attestation", "verified"),
                1,
            ),
            (
                ("observation", "source", "source_parent_commit"),
                "1" * 40,
            ),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                receipt = pending_receipt()
                target = receipt
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_candidate_rerun_attempt_two_is_valid_in_both_states(self) -> None:
        for receipt in (pending_receipt(), verified_receipt()):
            with self.subTest(status=receipt["status"]):
                receipt["observation"]["candidate_attestation"][
                    "workflow_run_attempt"
                ] = 2
                self.validate(receipt)

    def test_candidate_subject_set_and_workflow_order_are_exact(self) -> None:
        for mutation in ("missing", "extra", "order", "digest-key"):
            with self.subTest(mutation=mutation):
                receipt = pending_receipt()
                subjects = receipt["observation"]["candidate_attestation"][
                    "subjects"
                ]
                if mutation == "missing":
                    subjects.pop()
                elif mutation == "extra":
                    subjects.append(_sha256_subject("unexpected", _digest(99)))
                elif mutation == "order":
                    subjects[0], subjects[1] = subjects[1], subjects[0]
                else:
                    subjects[0]["digest"] = {"sha512": _digest(99)}
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_source_security_gate_is_structural_and_subject_crosslinked(self) -> None:
        for mutation in (
            "receipt-digest",
            "source-parent",
            "legacy-security-schema",
            "failed-ct",
            "missing-codeql",
            "wrong-codeql-tool-version",
            "open-code-scanning-alert",
            "workflow-path",
        ):
            with self.subTest(mutation=mutation):
                receipt = pending_receipt()
                candidate = receipt["observation"]["candidate_attestation"]
                gate = candidate["security_gate"]
                if mutation == "receipt-digest":
                    gate["receipt_sha256"] = _digest(140)
                elif mutation == "source-parent":
                    gate["source_parent_commit"] = "9" * 40
                elif mutation == "legacy-security-schema":
                    gate["schema_version"] = 1
                elif mutation == "failed-ct":
                    gate["workflows"]["ci"]["jobs"][0]["conclusion"] = "failure"
                elif mutation == "missing-codeql":
                    gate["workflows"]["codeql"]["jobs"].pop()
                elif mutation == "wrong-codeql-tool-version":
                    gate["code_scanning"]["analyses"][0]["tool"]["version"] = (
                        "2.26.1"
                    )
                elif mutation == "open-code-scanning-alert":
                    gate["code_scanning"]["open_alerts"] = [{"number": 1}]
                else:
                    gate["workflows"]["ci"]["workflow_path"] = (
                        ".github/workflows/other.yml"
                    )
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_verified_state_accepts_dynamic_future_hashes(self) -> None:
        receipt = verified_receipt()
        self.validate(receipt)

        changed = copy.deepcopy(receipt)
        replacement = _digest(120)
        asset_index = contract.PUBLIC_ASSET_NAMES.index(contract.ANDROID_AAR)
        changed["observation"]["assets"][asset_index]["sha256"] = replacement
        candidate_index = contract.CANDIDATE_SUBJECT_NAMES.index(
            contract.ANDROID_AAR
        )
        changed["observation"]["candidate_attestation"]["subjects"][
            candidate_index
        ]["digest"]["sha256"] = replacement
        changed["observation"]["release_candidate"]["assets"][asset_index][
            "sha256"
        ] = replacement
        changed["observation"]["release_attestation"]["subjects"][
            asset_index + 1
        ]["digest"]["sha256"] = replacement
        changed["observation"]["android_runtime_evidence"][
            "tested_aar_sha256"
        ] = replacement
        changed["observation"]["release_candidate"][
            "android_runtime_evidence"
        ]["tested_aar_sha256"] = replacement
        self.validate(changed)

    def test_public_assets_and_release_subjects_are_exact_and_ordered(self) -> None:
        for target, mutation in (
            ("assets", "order"),
            ("assets", "boolean-size"),
            ("release-subjects", "order"),
            ("release-subjects", "tag-uri"),
        ):
            with self.subTest(target=target, mutation=mutation):
                receipt = verified_receipt()
                if target == "assets":
                    assets = receipt["observation"]["assets"]
                    if mutation == "order":
                        assets[0], assets[1] = assets[1], assets[0]
                    else:
                        assets[0]["bytes"] = True
                else:
                    subjects = receipt["observation"]["release_attestation"][
                        "subjects"
                    ]
                    if mutation == "order":
                        subjects[1], subjects[2] = subjects[2], subjects[1]
                    else:
                        subjects[0]["uri"] += "-other"
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_every_publication_digest_family_is_crosslinked(self) -> None:
        mutations = (
            ("candidate", contract.ANDROID_AAR),
            ("distribution", None),
            ("checksums", None),
            ("release-subject", contract.LINUX_X86_64),
            ("runtime-bundle", None),
            ("runtime-aar", None),
            ("runtime-manifest", None),
            ("tag-subject", None),
            ("fresh-commit", None),
        )
        for mutation, name in mutations:
            with self.subTest(mutation=mutation):
                receipt = verified_receipt()
                observation = receipt["observation"]
                if mutation == "candidate":
                    index = contract.CANDIDATE_SUBJECT_NAMES.index(name)
                    observation["candidate_attestation"]["subjects"][index][
                        "digest"
                    ]["sha256"] = _digest(130)
                elif mutation == "distribution":
                    observation["platform_distribution_sha256"] = _digest(131)
                elif mutation == "checksums":
                    observation["checksums_sha256"] = _digest(132)
                elif mutation == "release-subject":
                    index = contract.PUBLIC_ASSET_NAMES.index(name) + 1
                    observation["release_attestation"]["subjects"][index][
                        "digest"
                    ]["sha256"] = _digest(133)
                elif mutation == "runtime-bundle":
                    observation["android_runtime_evidence"][
                        "bundle_sha256"
                    ] = _digest(134)
                elif mutation == "runtime-aar":
                    observation["android_runtime_evidence"][
                        "tested_aar_sha256"
                    ] = _digest(135)
                elif mutation == "runtime-manifest":
                    observation["android_runtime_evidence"][
                        "tested_aar_manifest_sha256"
                    ] = _digest(136)
                elif mutation == "tag-subject":
                    observation["release_attestation"]["subjects"][0][
                        "digest"
                    ]["sha1"] = "9" * 40
                else:
                    observation["fresh_download_verification"][
                        "verifier_commit"
                    ] = "9" * 40
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_timestamp_order_is_state_specific_and_strict(self) -> None:
        pending = pending_receipt()
        pending["observation"]["candidate_attestation"][
            "verified_at"
        ] = "2026-08-14T04:00:01Z"
        with self.assertRaisesRegex(
            contract.PlatformV014PublicationContractError,
            "postdates observation",
        ):
            self.validate(pending)

        for field, value in (
            ("published_at", "2026-08-14T00:59:59Z"),
            ("published_at", "2026-08-14 02:00:00Z"),
            ("fresh_verified_at", "2026-08-14T01:59:59Z"),
            ("observed_at", "2026-08-14T02:59:59Z"),
        ):
            with self.subTest(field=field):
                receipt = verified_receipt()
                if field == "fresh_verified_at":
                    receipt["observation"]["fresh_download_verification"][
                        "verified_at"
                    ] = value
                else:
                    receipt["observation"][field] = value
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_verified_runtime_registry_and_release_state_are_exact(
        self,
    ) -> None:
        mutations = (
            ("bundle_schema", 1),
            ("proof_schema", 5),
            ("device_kind", "physical"),
            ("device_abi", "x86_64"),
            ("device_sdk", 34),
            ("page_size", 4_096),
            ("release_mode", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                receipt = verified_receipt()
                receipt["observation"]["android_runtime_evidence"][field] = value
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

        receipt = verified_receipt()
        receipt["observation"]["registries"]["crates_io"] = "published"
        with self.assertRaises(
            contract.PlatformV014PublicationContractError
        ):
            self.validate(receipt)

        for field, value in (
            ("draft", True),
            ("prerelease", True),
            ("public_release", False),
            ("immutable_release", False),
            ("release_asset_verification_count", True),
            ("release_id", True),
        ):
            with self.subTest(field=field):
                receipt = verified_receipt()
                receipt["observation"][field] = value
                with self.assertRaises(
                    contract.PlatformV014PublicationContractError
                ):
                    self.validate(receipt)

    def test_v0_1_4_identity_and_current_proof_schema_authority_are_explicit(
        self,
    ) -> None:
        # The active platform identity deliberately derives from the
        # current candidate contract, so the version sweep that bumps
        # platform_distribution_contract to 0.1.4 needs no change here.
        self.assertEqual(
            contract.PRODUCT_VERSION,
            current_distribution_contract.PRODUCT_VERSION,
        )
        self.assertEqual(contract.DISTRIBUTION_REVISION, "r1")
        self.assertEqual(
            contract.RELEASE_TAG,
            current_distribution_contract.RELEASE_TAG,
        )
        self.assertEqual(
            contract.PLATFORM_V0_1_4_PUBLICATION_KEY,
            "platform_v0_1_4",
        )
        self.assertNotIn(
            "zero-result",
            contract.PLATFORM_V0_1_4_PUBLICATION_BOUNDARY,
        )
        self.assertIn(
            "zero unadjudicated findings",
            contract.PLATFORM_V0_1_4_PUBLICATION_BOUNDARY,
        )
        self.assertEqual(
            contract.CANDIDATE_SUBJECT_NAMES,
            current_distribution_contract.PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
        )
        self.assertEqual(
            contract.CANDIDATE_PUBLIC_ASSET_NAMES,
            frozenset(current_distribution_contract.PLATFORM_CANDIDATE_ASSETS),
        )
        self.assertEqual(
            contract.PUBLIC_ASSET_NAMES,
            tuple(sorted(current_distribution_contract.PLATFORM_RELEASE_FILES)),
        )
        self.assertEqual(
            contract.PUBLIC_ASSET_NAMES,
            tuple(contract.PUBLIC_ASSET_CONTENT_TYPES),
        )
        self.assertIs(
            contract.PUBLIC_ASSET_CONTENT_TYPES,
            current_distribution_contract.PUBLIC_ASSET_CONTENT_TYPES,
        )
        self.assertEqual(
            {
                current_distribution_contract.RELEASE_MANIFEST: "application/json",
                current_distribution_contract.RELEASE_SUMS: "application/octet-stream",
                current_distribution_contract.ANDROID_RUNTIME_BUNDLE: "application/zip",
                current_distribution_contract.ANDROID_MANIFEST: "application/json",
                current_distribution_contract.ANDROID_AAR: "application/octet-stream",
                current_distribution_contract.LINUX_AARCH64: "application/x-gtar",
                current_distribution_contract.LINUX_X86_64: "application/x-gtar",
            },
            dict(contract.PUBLIC_ASSET_CONTENT_TYPES),
        )
        with self.assertRaises(TypeError):
            operator.setitem(
                contract.PUBLIC_ASSET_CONTENT_TYPES,
                contract.ANDROID_AAR,
                "application/octet-stream",
            )
        self.assertEqual(contract.PLATFORM_V0_1_4_PUBLICATION_SCHEMA_VERSION, 3)
        self.assertEqual(
            current_distribution_contract.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
            android_device_proof.PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(contract.ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION, 2)
        self.assertEqual(contract.ANDROID_DEVICE_PROOF_SCHEMA_VERSION, 6)


if __name__ == "__main__":
    unittest.main()
