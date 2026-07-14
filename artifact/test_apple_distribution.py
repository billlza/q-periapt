#!/usr/bin/env python3
"""Regression tests for fail-closed Apple signing and notarization evidence."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock

import apple_distribution


SUBMISSION_ID = "2efe2717-52ef-43a5-96dc-0797e4ca1041"
ARTIFACT_NAME = "CQPeriapt.xcframework.zip"
CERTIFICATE_SHA256 = "80" * 32
CDHASH = "0123456789abcdef0123456789abcdef01234567"
SOURCE_COMMIT = "ab" * 20


def serialized_sha256(document: dict[str, object]) -> str:
    data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def codesign_display(*, team_id: str = "YKUPL7Z869", timestamp: bool = True) -> str:
    lines = [
        "Identifier=CQPeriapt",
        "Format=bundle with generic",
        "CodeDirectory v=20500 size=492 flags=0x0(none) hashes=4+7 location=embedded",
        "Signature size=9078",
        "Authority=Developer ID Application: Example (YKUPL7Z869)",
        "Authority=Developer ID Certification Authority",
        "Authority=Apple Root CA",
    ]
    if timestamp:
        lines.append("Timestamp=Jul 14, 2026 at 10:00:00")
    lines.extend(
        [
            f"TeamIdentifier={team_id}",
            "Sealed Resources version=2 rules=13 files=10",
            "Internal requirements count=1 size=180",
            f"CDHash={CDHASH}",
        ]
    )
    return "\n".join(lines) + "\n"


class CodesignDisplayTests(unittest.TestCase):
    def test_accepts_pinned_developer_id_chain_and_timestamp(self) -> None:
        parsed = apple_distribution.parse_codesign_display(
            codesign_display(),
            expected_team_id="YKUPL7Z869",
        )
        self.assertEqual(parsed["identity_class"], "Developer ID Application")
        self.assertEqual(parsed["team_id"], "YKUPL7Z869")
        self.assertEqual(parsed["cdhash"], CDHASH)
        self.assertFalse(parsed["hardened_runtime"])
        self.assertEqual(parsed["code_directory_flags"], "none")

    def test_rejects_missing_secure_timestamp(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "exactly one non-empty Timestamp",
        ):
            apple_distribution.parse_codesign_display(
                codesign_display(timestamp=False),
                expected_team_id="YKUPL7Z869",
            )

    def test_rejects_wrong_team(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "does not match",
        ):
            apple_distribution.parse_codesign_display(
                codesign_display(team_id="ABCDEFGHIJ"),
                expected_team_id="YKUPL7Z869",
            )

    def test_rejects_hardened_runtime_on_static_sdk(self) -> None:
        display = codesign_display() + "Runtime Version=26.0.0\n"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "hardened runtime",
        ):
            apple_distribution.parse_codesign_display(
                display,
                expected_team_id="YKUPL7Z869",
            )

    def test_rejects_nonzero_code_directory_flags(self) -> None:
        display = codesign_display().replace("flags=0x0(none)", "flags=0x10000(runtime)")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "CodeDirectory flags are not exactly none",
        ):
            apple_distribution.parse_codesign_display(
                display,
                expected_team_id="YKUPL7Z869",
            )


class SigningEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.xcframework = self.root / "CQPeriapt.xcframework"
        for relative in apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES:
            library = self.xcframework / relative
            library.parent.mkdir(parents=True, exist_ok=True)
            library.write_bytes(f"slice:{relative}".encode("utf-8"))
        code_resources = self.xcframework / "_CodeSignature" / "CodeResources"
        code_resources.parent.mkdir(parents=True)
        code_resources.write_bytes(b"sealed-resources")
        self.display = self.root / "codesign-display.txt"
        self.display.write_text(codesign_display(), encoding="utf-8")
        self.certificate = self.root / "certificate.der"
        self.certificate.write_bytes(b"pinned-developer-id-certificate")
        certificate_bytes = self.certificate.read_bytes()
        self.identity_sha1 = hashlib.sha1(
            certificate_bytes, usedforsecurity=False
        ).hexdigest()
        self.certificate_sha256 = hashlib.sha256(certificate_bytes).hexdigest()
        self.certificate_metadata = {
            "subject": "CN=Developer ID Application: Example (YKUPL7Z869)",
            "issuer": "CN=Developer ID Certification Authority",
            "serial": "01",
            "notBefore": "Jul 1 00:00:00 2026 GMT",
            "notAfter": "Jul 1 00:00:00 2027 GMT",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, *, certificate_sha256: str | None = None) -> dict[str, object]:
        with mock.patch.object(
            apple_distribution,
            "_openssl_certificate_metadata",
            return_value=self.certificate_metadata,
        ):
            return apple_distribution.build_signing_evidence(
                xcframework=self.xcframework,
                codesign_display=self.display,
                certificate=self.certificate,
                expected_team_id="YKUPL7Z869",
                expected_identity_sha1=self.identity_sha1,
                expected_certificate_sha256=(
                    certificate_sha256 or self.certificate_sha256
                ),
            )

    def test_builds_evidence_for_exact_pinned_signed_xcframework(self) -> None:
        evidence = self.build()
        self.assertEqual(evidence["certificate"]["sha1"], self.identity_sha1)
        self.assertEqual(
            set(evidence["sealed_resources"]["static_libraries"]),
            apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES,
        )

    def test_rejects_wrong_pinned_certificate_hash(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "SHA-256 does not match",
        ):
            self.build(certificate_sha256="00" * 32)

    def test_rejects_missing_or_extra_static_slice(self) -> None:
        missing = self.xcframework / sorted(
            apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES
        )[0]
        missing.unlink()
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "unexpected signed XCFramework library set",
        ):
            self.build()
        missing.write_bytes(b"restored-slice")
        extra = self.xcframework / "macos-arm64/extra.a"
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b"extra-slice")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "unexpected signed XCFramework library set",
        ):
            self.build()

    def test_rejects_missing_code_resources_with_context(self) -> None:
        (self.xcframework / "_CodeSignature" / "CodeResources").unlink()
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "cannot open XCFramework CodeResources",
        ):
            self.build()


class NotarizationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.artifact = self.root / ARTIFACT_NAME
        self.artifact.write_bytes(b"signed-xcframework-zip")
        self.artifact_sha256 = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.submit = {
            "id": SUBMISSION_ID,
            "message": "Successfully uploaded file",
        }
        self.info = {
            "createdDate": "2026-07-14T02:00:00.000Z",
            "id": SUBMISSION_ID,
            "name": ARTIFACT_NAME,
            "status": "Accepted",
        }
        self.log = {
            "logFormatVersion": 1,
            "jobId": SUBMISSION_ID,
            "status": "Accepted",
            "statusSummary": "Ready for distribution",
            "statusCode": 0,
            "archiveFilename": ARTIFACT_NAME,
            "uploadDate": "2026-07-14T02:00:01.000Z",
            "sha256": self.artifact_sha256,
            "ticketContents": [
                {
                    "path": "CQPeriapt.xcframework.zip/CQPeriapt.xcframework",
                    "digestAlgorithm": "SHA-256",
                    "cdhash": CDHASH,
                }
            ],
            "issues": None,
        }
        self.signing = {
            "schema_version": 1,
            "kind": "qperiapt.apple_xcframework_signature",
            "signature": {
                "identity_class": "Developer ID Application",
                "team_id": "YKUPL7Z869",
                "cdhash": CDHASH,
            },
            "certificate": {"sha256": CERTIFICATE_SHA256},
        }
        self.signing_sha256 = "44" * 32
        self.prepared = apple_distribution.build_prepared_submission_state(
            artifact=self.artifact,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.prepared_sha256 = serialized_sha256(self.prepared)
        self.submit_sha256: str | None = "11" * 32
        self.submit_document: dict[str, object] | None = self.submit
        self.submit_capture: bytes | None = None
        self.state = apple_distribution.build_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submit_document=self.submit,
            submit_response_sha256=self.submit_sha256,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.state_sha256 = serialized_sha256(self.state)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict[str, object]:
        return apple_distribution.build_notarization_evidence(
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            submission_state=self.state,
            submission_state_sha256=self.state_sha256,
            source_commit=SOURCE_COMMIT,
            submit_document=self.submit_document,
            submit_capture=self.submit_capture,
            info_document=self.info,
            log_document=self.log,
            submit_sha256=self.submit_sha256,
            info_sha256="22" * 32,
            log_sha256="33" * 32,
            signing_evidence=self.signing,
            signing_evidence_sha256=self.signing_sha256,
        )

    def test_accepts_one_hash_bound_warning_free_ticketed_submission(self) -> None:
        evidence = self.build()
        self.assertEqual(evidence["artifact"]["sha256"], self.artifact_sha256)
        self.assertEqual(evidence["submission"]["id"], SUBMISSION_ID)
        self.assertEqual(evidence["submission"]["ticket_count"], 1)
        self.assertEqual(evidence["submission"]["matching_signer_ticket_count"], 1)
        self.assertEqual(evidence["submission"]["issue_count"], 0)
        self.assertEqual(
            evidence["submission"]["id_provenance"],
            "notarytool_submit_response",
        )
        self.assertEqual(evidence["raw_evidence_sha256"]["submit"], "11" * 32)
        self.assertEqual(
            evidence["raw_evidence_sha256"]["prepared_state"],
            self.prepared_sha256,
        )
        self.assertFalse(evidence["stapling"]["supported"])
        self.assertEqual(evidence["signer"]["team_id"], "YKUPL7Z869")
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("private-notary-profile", serialized)
        self.assertNotIn("keychain", serialized.lower())

    def test_accepts_explicit_empty_issue_array(self) -> None:
        self.log["issues"] = []
        self.assertEqual(self.build()["submission"]["status"], "Accepted")

    def test_accepts_explicit_uuid_recovery_without_fabricated_submit_response(self) -> None:
        self.submit_capture = b'{"id":'
        self.state = apple_distribution.build_recovered_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            submit_capture=self.submit_capture,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.state_sha256 = serialized_sha256(self.state)
        self.submit_document = None
        self.submit_sha256 = None
        evidence = self.build()
        self.assertEqual(
            evidence["submission"]["id_provenance"],
            "explicit_uuid_recovery",
        )
        self.assertNotIn("submit", evidence["raw_evidence_sha256"])

    def test_recovery_state_rejects_claimed_submit_response(self) -> None:
        self.submit_capture = b'{"id":'
        self.state = apple_distribution.build_recovered_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            submit_capture=self.submit_capture,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.state_sha256 = serialized_sha256(self.state)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "must not claim a notarytool submit response",
        ):
            self.build()

    def test_rejects_nonaccepted_info(self) -> None:
        self.info["status"] = "In Progress"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "info status is not Accepted",
        ):
            self.build()

    def test_rejects_submission_id_mismatch(self) -> None:
        self.log["jobId"] = "00000000-0000-4000-8000-000000000000"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "jobId does not match",
        ):
            self.build()

    def test_rejects_artifact_hash_mismatch(self) -> None:
        self.log["sha256"] = "00" * 32
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "SHA-256 does not match",
        ):
            self.build()

    def test_rejects_warning_bearing_accepted_log(self) -> None:
        self.log["issues"] = [
            {
                "severity": "warning",
                "message": "fix this before release",
            }
        ]
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "contains issues",
        ):
            self.build()

    def test_rejects_accepted_log_without_ticket(self) -> None:
        self.log["ticketContents"] = []
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "no ticket contents",
        ):
            self.build()

    def test_rejects_missing_issues_field(self) -> None:
        del self.log["issues"]
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "lacks the required issues field",
        ):
            self.build()

    def test_rejects_unknown_log_schema(self) -> None:
        self.log["logFormatVersion"] = 2
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "format version is not 1",
        ):
            self.build()

    def test_rejects_ticket_cdhash_not_bound_to_signature(self) -> None:
        self.log["ticketContents"][0]["cdhash"] = "00" * 20
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "exactly one binding",
        ):
            self.build()

    def test_rejects_ticket_for_wrong_bundle_path(self) -> None:
        self.log["ticketContents"][0]["path"] = "Other.zip/Other.xcframework"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "path must be exactly",
        ):
            self.build()

    def test_rejects_nested_same_named_ticket_path(self) -> None:
        self.log["ticketContents"][0]["path"] = (
            f"{ARTIFACT_NAME}/nested/CQPeriapt.xcframework"
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "path must be exactly",
        ):
            self.build()

    def test_rejects_additional_ticket_even_when_one_path_is_exact(self) -> None:
        self.log["ticketContents"].append(dict(self.log["ticketContents"][0]))
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "exactly one ticket",
        ):
            self.build()

    def test_rejects_ticket_with_wrong_digest_algorithm(self) -> None:
        self.log["ticketContents"][0]["digestAlgorithm"] = "SHA-1"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "digestAlgorithm is not SHA-256",
        ):
            self.build()

    def test_rejects_invalid_signer(self) -> None:
        self.signing["signature"]["identity_class"] = "Apple Development"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "identity class is not Developer ID Application",
        ):
            self.build()

    def test_strict_submit_parser_rejects_duplicate_id(self) -> None:
        submit_path = self.root / "submit.json"
        submit_path.write_text(
            '{"id":"' + SUBMISSION_ID + '","id":"' + SUBMISSION_ID + '"}\n',
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = apple_distribution.main(
                ["submission-id", "--submit", str(submit_path)]
            )
        self.assertEqual(result, 2)
        self.assertIn("duplicate JSON key", stderr.getvalue())


class SubmissionStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.artifact = self.root / ARTIFACT_NAME
        self.artifact.write_bytes(b"exact-submitted-zip")
        self.signing_sha256 = "ab" * 32
        self.submit = {"id": SUBMISSION_ID}
        self.submit_sha256 = "ef" * 32
        self.submit_capture = b'{"id":'
        self.prepared = apple_distribution.build_prepared_submission_state(
            artifact=self.artifact,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.prepared_sha256 = serialized_sha256(self.prepared)
        self.state = apple_distribution.build_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submit_document=self.submit,
            submit_response_sha256=self.submit_sha256,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self) -> str:
        return apple_distribution.validate_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            state=self.state,
            artifact=self.artifact,
            signing_evidence_sha256=self.signing_sha256,
            expected_submission_id=SUBMISSION_ID,
            expected_source_commit=SOURCE_COMMIT,
            submit_document=self.submit,
            submit_response_sha256=self.submit_sha256,
        )

    def test_exact_state_resumes_same_submission(self) -> None:
        self.assertEqual(self.validate(), SUBMISSION_ID)

    def test_changed_zip_fails_closed(self) -> None:
        self.artifact.write_bytes(b"newly-signed-different-zip")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "artifact size does not match|artifact SHA-256 does not match",
        ):
            self.validate()

    def test_changed_signing_evidence_fails_closed(self) -> None:
        self.signing_sha256 = "cd" * 32
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "signing evidence SHA-256 does not match",
        ):
            self.validate()

    def test_changed_source_or_uuid_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "source commit does not match",
        ):
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=self.state,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id=SUBMISSION_ID,
                expected_source_commit="cd" * 20,
                submit_document=self.submit,
                submit_response_sha256=self.submit_sha256,
            )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "UUID does not match",
        ):
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=self.state,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id="00000000-0000-4000-8000-000000000000",
                expected_source_commit=SOURCE_COMMIT,
                submit_document=self.submit,
                submit_response_sha256=self.submit_sha256,
            )

    def test_unknown_state_field_fails_closed(self) -> None:
        self.state["fallback"] = True
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "fields differ from the release schema",
        ):
            self.validate()

    def test_state_provenance_reader_is_strict_and_has_no_fallback(self) -> None:
        self.assertEqual(
            apple_distribution.submission_state_provenance(self.state),
            "notarytool_submit_response",
        )
        self.state["submission_id_provenance"]["fallback"] = True
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "provenance fields differ",
        ):
            apple_distribution.submission_state_provenance(self.state)
        self.state["submission_id_provenance"] = {"kind": "unknown"}
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "unknown notary submission provenance kind",
        ):
            apple_distribution.submission_state_provenance(self.state)

    def test_prepared_state_hash_is_part_of_the_bound_state(self) -> None:
        self.prepared_sha256 = "00" * 32
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "prepared state SHA-256 does not match",
        ):
            self.validate()

    def test_normal_state_requires_the_exact_submit_response(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "requires its submit response",
        ):
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=self.state,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id=SUBMISSION_ID,
                expected_source_commit=SOURCE_COMMIT,
            )
        self.submit_sha256 = "00" * 32
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "submit response SHA-256 does not match",
        ):
            self.validate()

    def test_explicit_uuid_recovery_is_distinct_and_resumable(self) -> None:
        recovered = apple_distribution.build_recovered_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            submit_capture=self.submit_capture,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.assertEqual(
            recovered["submission_id_provenance"],
            {
                "kind": "explicit_uuid_recovery",
                "captured_stdout": {
                    "size": len(self.submit_capture),
                    "sha256": hashlib.sha256(self.submit_capture).hexdigest(),
                    "parse_status": "invalid_or_truncated_json",
                },
            },
        )
        self.assertEqual(
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=recovered,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id=SUBMISSION_ID,
                expected_source_commit=SOURCE_COMMIT,
                submit_capture=self.submit_capture,
            ),
            SUBMISSION_ID,
        )

    def test_explicit_uuid_recovery_accepts_durable_empty_capture(self) -> None:
        empty_capture = b""
        recovered = apple_distribution.build_recovered_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            submit_capture=empty_capture,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        self.assertEqual(
            recovered["submission_id_provenance"]["captured_stdout"],
            {
                "size": 0,
                "sha256": hashlib.sha256(empty_capture).hexdigest(),
                "parse_status": "invalid_or_truncated_json",
            },
        )
        self.assertEqual(
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=recovered,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id=SUBMISSION_ID,
                expected_source_commit=SOURCE_COMMIT,
                submit_capture=empty_capture,
            ),
            SUBMISSION_ID,
        )

    def test_complete_valid_submit_capture_must_use_normal_path(self) -> None:
        complete_capture = json.dumps({"id": SUBMISSION_ID}).encode("utf-8")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "contains a valid submission UUID; use the normal",
        ):
            apple_distribution.build_recovered_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                artifact=self.artifact,
                submission_id=SUBMISSION_ID,
                submit_capture=complete_capture,
                signing_evidence_sha256=self.signing_sha256,
                source_commit=SOURCE_COMMIT,
            )

    def test_recovered_state_capture_tampering_fails_closed(self) -> None:
        recovered = apple_distribution.build_recovered_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            submit_capture=self.submit_capture,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        recovered["submission_id_provenance"]["captured_stdout"]["sha256"] = "00" * 32
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "captured_stdout differs from the preserved capture",
        ):
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=recovered,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id=SUBMISSION_ID,
                expected_source_commit=SOURCE_COMMIT,
                submit_capture=self.submit_capture,
            )

    def test_recovery_rejects_submit_response_instead_of_relabeling_it(self) -> None:
        recovered = apple_distribution.build_recovered_submission_state(
            prepared_state=self.prepared,
            prepared_state_sha256=self.prepared_sha256,
            artifact=self.artifact,
            submission_id=SUBMISSION_ID,
            submit_capture=self.submit_capture,
            signing_evidence_sha256=self.signing_sha256,
            source_commit=SOURCE_COMMIT,
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "must not claim a notarytool submit response",
        ):
            apple_distribution.validate_submission_state(
                prepared_state=self.prepared,
                prepared_state_sha256=self.prepared_sha256,
                state=recovered,
                artifact=self.artifact,
                signing_evidence_sha256=self.signing_sha256,
                expected_submission_id=SUBMISSION_ID,
                expected_source_commit=SOURCE_COMMIT,
                submit_document=self.submit,
                submit_response_sha256=self.submit_sha256,
                submit_capture=self.submit_capture,
            )

    def test_prepared_state_is_strict_and_binds_the_release_inputs(self) -> None:
        self.prepared["fallback"] = True
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "prepared notary submission state fields differ",
        ):
            self.validate()


class AtomicEvidenceWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.output = self.root / "state.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def temporary_outputs(self) -> list[pathlib.Path]:
        return list(self.root.glob(".state.json.tmp.*"))

    def test_atomically_publishes_complete_private_json_and_syncs_directory(self) -> None:
        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            wraps=apple_distribution.os.fsync,
        ) as fsync:
            apple_distribution._write_new_json(self.output, {"value": "complete"})
        self.assertEqual(
            json.loads(self.output.read_text(encoding="utf-8")),
            {"value": "complete"},
        )
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(fsync.call_count, 5)
        self.assertEqual(self.temporary_outputs(), [])

    def test_existing_output_is_never_replaced_or_truncated(self) -> None:
        self.output.write_bytes(b"immutable-existing-state\n")
        with self.assertRaises(FileExistsError):
            apple_distribution._write_new_json(self.output, {"replacement": True})
        self.assertEqual(self.output.read_bytes(), b"immutable-existing-state\n")
        self.assertEqual(self.temporary_outputs(), [])

    def test_failed_publication_leaves_no_partial_final_name(self) -> None:
        with mock.patch.object(
            apple_distribution.os,
            "link",
            side_effect=OSError("injected publication failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected publication failure"):
                apple_distribution._write_new_json(self.output, {"value": "partial"})
        self.assertFalse(self.output.exists())
        self.assertEqual(self.temporary_outputs(), [])

    def test_existing_symlink_output_is_not_followed(self) -> None:
        target = self.root / "target.json"
        target.write_bytes(b"target-must-not-change\n")
        self.output.symlink_to(target)
        with self.assertRaises(FileExistsError):
            apple_distribution._write_new_json(self.output, {"replacement": True})
        self.assertEqual(target.read_bytes(), b"target-must-not-change\n")
        self.assertTrue(self.output.is_symlink())

    def test_submit_capture_exists_durably_before_network_and_flushes_afterward(self) -> None:
        capture = self.root / "submit.capture.json"
        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            wraps=apple_distribution.os.fsync,
        ) as fsync, mock.patch.object(
            apple_distribution.sys,
            "platform",
            "darwin",
        ), mock.patch.object(
            apple_distribution.fcntl,
            "F_FULLFSYNC",
            51,
            create=True,
        ), mock.patch.object(
            apple_distribution.fcntl,
            "fcntl",
            return_value=0,
        ) as full_fsync:
            apple_distribution.prepare_submit_capture(capture)
            self.assertEqual(capture.read_bytes(), b"")
            self.assertEqual(capture.stat().st_mode & 0o777, 0o600)
            with capture.open("ab") as stream:
                stream.write(b'{"id":')
            apple_distribution.finalize_submit_capture(capture)
        self.assertEqual(capture.read_bytes(), b'{"id":')
        self.assertGreaterEqual(fsync.call_count, 7)
        self.assertEqual(full_fsync.call_count, 2)
        self.assertTrue(
            all(call.args[1] == 51 for call in full_fsync.call_args_list)
        )

    def test_submit_capture_preparation_never_replaces_existing_path(self) -> None:
        capture = self.root / "submit.capture.json"
        capture.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            apple_distribution.prepare_submit_capture(capture)
        self.assertEqual(capture.read_bytes(), b"preserve")

    def test_submit_capture_finalization_rejects_symlink(self) -> None:
        target = self.root / "target.capture"
        target.write_bytes(b"target")
        capture = self.root / "submit.capture.json"
        capture.symlink_to(target)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "cannot open notary submit stdout capture",
        ):
            apple_distribution.finalize_submit_capture(capture)
        self.assertEqual(target.read_bytes(), b"target")


class ReleaseTreeDurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.anchor = pathlib.Path(self.temporary.name) / "main-worktree"
        self.private_release_root = (
            self.anchor
            / "target"
            / "qperiapt-apple-release-worktrees"
            / SOURCE_COMMIT
        )
        self.repository = self.private_release_root / "source"
        self.release = self.repository / "target" / "release-output"
        self.product = (
            self.release
            / "consumer"
            / ".build"
            / "arm64-apple-macosx"
            / "debug"
        )
        self.product.mkdir(parents=True)
        self.private_release_root.chmod(0o700)
        self.git_admin = self.anchor / ".git" / "worktrees" / "source"
        self.git_admin.mkdir(parents=True)
        self.main_git_index = self.anchor / ".git" / "index"
        self.main_git_index.write_bytes(b"main-index")
        self.main_git_ref = self.anchor / ".git" / "refs" / "heads" / "release-abi2"
        self.main_git_ref.parent.mkdir(parents=True)
        self.main_git_ref.write_text(SOURCE_COMMIT + "\n", encoding="ascii")
        self.main_git_object = self.anchor / ".git" / "objects" / "aa" / ("b" * 38)
        self.main_git_object.parent.mkdir(parents=True)
        self.main_git_object.write_bytes(b"loose-object")
        (self.git_admin / "HEAD").write_text(SOURCE_COMMIT + "\n", encoding="utf-8")
        (self.git_admin / "commondir").write_text("../..\n", encoding="utf-8")
        (self.git_admin / "gitdir").write_text(
            str(self.repository / ".git") + "\n",
            encoding="utf-8",
        )
        (self.repository / ".git").write_text(
            f"gitdir: {self.git_admin}\n",
            encoding="utf-8",
        )
        self.source_file = self.repository / "README.md"
        self.source_file.write_bytes(b"durable-source")
        self.unrelated_target_file = self.repository / "target" / "unrelated-build-cache"
        self.unrelated_target_file.write_bytes(b"excluded-rebuildable-output")
        self.probe = self.product / "QPeriaptLinkProbe"
        self.probe.write_bytes(b"linked-probe")
        self.archive = self.release / "CQPeriapt.xcframework.zip"
        self.archive.write_bytes(b"signed-archive")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def sync(self) -> None:
        apple_distribution.durably_sync_release_tree(
            anchor_root=self.anchor,
            repository_root=self.repository,
            release_root=self.release,
            expected_source_commit=SOURCE_COMMIT,
        )

    def cli_arguments(self) -> list[str]:
        return [
            "sync-release-tree",
            "--anchor-root",
            str(self.anchor),
            "--repository-root",
            str(self.repository),
            "--root",
            str(self.release),
            "--source-commit",
            SOURCE_COMMIT,
        ]

    def test_syncs_nested_files_directories_and_internal_swiftpm_symlink(self) -> None:
        swift_build = self.release / "consumer" / ".build"
        (swift_build / "debug").symlink_to("arm64-apple-macosx/debug")
        permissive_tool_directory = self.release / "consumer" / ".swiftpm"
        permissive_tool_directory.mkdir()
        permissive_tool_directory.chmod(0o777)
        probe_inode = self.probe.stat().st_ino
        synced_inodes: list[int] = []
        real_fsync = apple_distribution.os.fsync

        def recording_fsync(descriptor: int) -> None:
            synced_inodes.append(apple_distribution.os.fstat(descriptor).st_ino)
            real_fsync(descriptor)

        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            side_effect=recording_fsync,
        ):
            self.sync()
        self.assertEqual(synced_inodes.count(probe_inode), 1)
        self.assertNotIn(self.unrelated_target_file.stat().st_ino, synced_inodes)
        for durable_file in (
            self.source_file,
            self.repository / ".git",
            self.main_git_index,
            self.main_git_ref,
            self.main_git_object,
            self.git_admin / "HEAD",
            self.git_admin / "gitdir",
            self.git_admin / "commondir",
        ):
            with self.subTest(durable_file=durable_file):
                self.assertIn(durable_file.stat().st_ino, synced_inodes)
        for durable_directory in (
            self.anchor,
            self.anchor / "target",
            self.private_release_root.parent,
            self.private_release_root,
            self.repository,
            self.repository / "target",
            self.release,
            self.anchor / ".git",
            self.anchor / ".git" / "worktrees",
            self.git_admin,
        ):
            with self.subTest(durable_directory=durable_directory):
                self.assertIn(durable_directory.stat().st_ino, synced_inodes)

    def test_final_barrier_follows_every_file_sync_and_is_the_last_write(self) -> None:
        events: list[tuple[str, int]] = []
        real_fsync = apple_distribution.os.fsync

        def recording_fsync(descriptor: int) -> None:
            events.append(("fsync", apple_distribution.os.fstat(descriptor).st_ino))
            real_fsync(descriptor)

        def recording_barrier(descriptor: int, command: int) -> int:
            self.assertEqual(command, 51)
            events.append(("barrier", apple_distribution.os.fstat(descriptor).st_ino))
            return 0

        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            side_effect=recording_fsync,
        ), mock.patch.object(
            apple_distribution.sys,
            "platform",
            "darwin",
        ), mock.patch.object(
            apple_distribution.fcntl,
            "F_FULLFSYNC",
            51,
            create=True,
        ), mock.patch.object(
            apple_distribution.fcntl,
            "fcntl",
            side_effect=recording_barrier,
        ):
            self.sync()

        self.assertEqual(events[-1], ("barrier", self.anchor.stat().st_ino))
        self.assertEqual(sum(kind == "barrier" for kind, _ in events), 1)
        barrier_position = len(events) - 1
        for durable_file in (
            self.source_file,
            self.probe,
            self.main_git_index,
            self.main_git_ref,
            self.main_git_object,
            self.git_admin / "HEAD",
        ):
            with self.subTest(durable_file=durable_file):
                inode = durable_file.stat().st_ino
                self.assertTrue(
                    any(
                        position < barrier_position and event == ("fsync", inode)
                        for position, event in enumerate(events)
                    )
                )

    def test_darwin_tree_sync_ends_with_one_full_device_barrier(self) -> None:
        barrier_inodes: list[int] = []

        def recording_barrier(descriptor: int, command: int) -> int:
            self.assertEqual(command, 51)
            barrier_inodes.append(apple_distribution.os.fstat(descriptor).st_ino)
            return 0

        with mock.patch.object(
            apple_distribution.sys,
            "platform",
            "darwin",
        ), mock.patch.object(
            apple_distribution.fcntl,
            "F_FULLFSYNC",
            51,
            create=True,
        ), mock.patch.object(
            apple_distribution.fcntl,
            "fcntl",
            side_effect=recording_barrier,
        ):
            self.sync()
        self.assertEqual(barrier_inodes, [self.anchor.stat().st_ino])

    def test_rejects_cross_tree_mutation_before_the_barrier(self) -> None:
        admin_head_inode = (self.git_admin / "HEAD").stat().st_ino
        mutated = False
        real_fsync = apple_distribution.os.fsync

        def racing_fsync(descriptor: int) -> None:
            nonlocal mutated
            real_fsync(descriptor)
            if (
                not mutated
                and apple_distribution.os.fstat(descriptor).st_ino == admin_head_inode
            ):
                self.probe.write_bytes(b"late-cross-tree-mutation")
                mutated = True

        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            side_effect=racing_fsync,
        ), mock.patch.object(
            apple_distribution.sys,
            "platform",
            "darwin",
        ), mock.patch.object(
            apple_distribution.fcntl,
            "F_FULLFSYNC",
            51,
            create=True,
        ), mock.patch.object(
            apple_distribution.fcntl,
            "fcntl",
            return_value=0,
        ) as full_fsync:
            with self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "synchronized release tree entry changed",
            ):
                self.sync()
        self.assertTrue(mutated)
        full_fsync.assert_not_called()

    def test_rejects_mutation_during_the_final_barrier(self) -> None:
        def mutating_barrier(descriptor: int, command: int) -> int:
            self.assertEqual(command, 51)
            self.source_file.write_bytes(b"mutation-during-barrier")
            return 0

        with mock.patch.object(
            apple_distribution.sys,
            "platform",
            "darwin",
        ), mock.patch.object(
            apple_distribution.fcntl,
            "F_FULLFSYNC",
            51,
            create=True,
        ), mock.patch.object(
            apple_distribution.fcntl,
            "fcntl",
            side_effect=mutating_barrier,
        ) as full_fsync:
            with self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "synchronized release tree entry changed",
            ):
                self.sync()
        full_fsync.assert_called_once()

    def test_rejects_ancestor_replacement_and_closes_every_open_descriptor(self) -> None:
        repository_inode = self.repository.stat().st_ino
        repository_target = self.repository / "target"
        preserved_target = self.repository / "target-preserved"
        real_open = apple_distribution.os.open
        real_close = apple_distribution.os.close
        opened: dict[int, int] = {}
        closed: dict[int, int] = {}
        replaced = False

        def racing_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal replaced
            if (
                not replaced
                and path == "target"
                and dir_fd is not None
                and apple_distribution.os.fstat(dir_fd).st_ino == repository_inode
            ):
                repository_target.rename(preserved_target)
                repository_target.mkdir()
                replaced = True
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            opened[descriptor] = opened.get(descriptor, 0) + 1
            return descriptor

        def recording_close(descriptor: int) -> None:
            closed[descriptor] = closed.get(descriptor, 0) + 1
            real_close(descriptor)

        with mock.patch.object(
            apple_distribution.os,
            "open",
            side_effect=racing_open,
        ), mock.patch.object(
            apple_distribution.os,
            "close",
            side_effect=recording_close,
        ):
            with self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "ancestor changed while it was opened",
            ):
                self.sync()
        self.assertTrue(replaced)
        self.assertEqual(closed, opened)

    def test_rejects_intermediate_ancestor_symlink(self) -> None:
        repository_target = self.repository / "target"
        preserved_target = self.repository / "target-preserved"
        repository_target.rename(preserved_target)
        repository_target.symlink_to(preserved_target.name, target_is_directory=True)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "ancestor is not a real directory",
        ):
            self.sync()

    def test_rejects_absolute_and_escaping_symlinks(self) -> None:
        sentinel = pathlib.Path(self.temporary.name) / "external-sentinel"
        sentinel.write_bytes(b"must-not-be-followed")
        for name, target in (
            ("absolute-link", str(sentinel)),
            ("escaping-link", "../../../../external-sentinel"),
        ):
            with self.subTest(name=name):
                link = self.release / name
                link.symlink_to(target)
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    "symlink target must be.*relative|symlink escapes",
                ):
                    self.sync()
                link.unlink()
                self.assertEqual(sentinel.read_bytes(), b"must-not-be-followed")

    def test_rejects_dangling_and_cyclic_internal_symlinks(self) -> None:
        dangling = self.release / "dangling"
        dangling.symlink_to("missing-target")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "target is not inside the synchronized tree",
        ):
            self.sync()
        dangling.unlink()

        first = self.release / "cycle-a"
        second = self.release / "cycle-b"
        first.symlink_to(second.name)
        second.symlink_to(first.name)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "symlink cycle",
        ):
            self.sync()

    def test_rejects_git_admin_pointer_outside_the_main_repository(self) -> None:
        external_admin = pathlib.Path(self.temporary.name) / "external-admin"
        external_admin.mkdir()
        (self.repository / ".git").write_text(
            f"gitdir: {external_admin}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "Git admin path escapes the main repository",
        ):
            self.sync()

    def test_rejects_git_admin_backpointer_mismatch(self) -> None:
        (self.git_admin / "gitdir").write_text(
            str(self.repository / ".different-git") + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "Git admin backpointer does not match",
        ):
            self.sync()

    def test_rejects_git_admin_commondir_mismatch(self) -> None:
        (self.git_admin / "commondir").write_text("../different\n", encoding="utf-8")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "common Git directory pointer is not canonical",
        ):
            self.sync()

    def test_rejects_git_admin_head_mismatch(self) -> None:
        (self.git_admin / "HEAD").write_text("cd" * 20 + "\n", encoding="ascii")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "Git admin HEAD does not match",
        ):
            self.sync()

    def test_rejects_external_git_object_alternates(self) -> None:
        alternates = self.anchor / ".git" / "objects" / "info" / "alternates"
        alternates.parent.mkdir(parents=True)
        alternates.write_text("/external/objects\n", encoding="utf-8")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "must not use external alternates",
        ):
            self.sync()

    def test_rejects_other_principal_writable_main_git_entries(self) -> None:
        unsafe_directory = self.anchor / ".git" / "objects" / "unsafe-directory"
        unsafe_directory.mkdir()
        for path, mode in (
            (self.main_git_index, 0o666),
            (unsafe_directory, 0o777),
        ):
            original_mode = stat.S_IMODE(path.stat().st_mode)
            with self.subTest(path=path, mode=oct(mode)):
                path.chmod(mode)
                try:
                    with self.assertRaisesRegex(
                        apple_distribution.AppleDistributionError,
                        "writable by another principal",
                    ):
                        self.sync()
                finally:
                    path.chmod(original_mode)

    def test_rejects_tree_budget_overruns_before_notary_submission(self) -> None:
        cases = (
            ("MAX_SOURCE_TREE_ENTRIES", 1, "maximum entry count"),
            ("MAX_SOURCE_TREE_REGULAR_BYTES", 1, "maximum regular-file bytes"),
            ("MAX_TREE_DEPTH", 0, "maximum directory depth"),
        )
        for constant, value, message in cases:
            with self.subTest(constant=constant), mock.patch.object(
                apple_distribution,
                constant,
                value,
            ):
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    message,
                ):
                    self.sync()

    def test_rejects_special_files_in_source_and_main_git_trees(self) -> None:
        for fifo in (
            self.repository / "unexpected-source-fifo",
            self.anchor / ".git" / "objects" / "unexpected-object-fifo",
        ):
            with self.subTest(fifo=fifo):
                fifo.parent.mkdir(parents=True, exist_ok=True)
                os.mkfifo(fifo)
                try:
                    with self.assertRaisesRegex(
                        apple_distribution.AppleDistributionError,
                        "unsupported file type",
                    ):
                        self.sync()
                finally:
                    fifo.unlink()

    def test_rejects_symlink_root_and_special_file(self) -> None:
        linked_root = self.repository / "target" / "linked-output"
        linked_root.symlink_to(self.release, target_is_directory=True)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "ancestor is not a real directory",
        ):
            apple_distribution.durably_sync_release_tree(
                anchor_root=self.anchor,
                repository_root=self.repository,
                release_root=linked_root,
                expected_source_commit=SOURCE_COMMIT,
            )

        fifo = self.release / "unexpected-fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "unsupported file type",
        ):
            self.sync()

    def test_rejects_file_mutation_during_fsync(self) -> None:
        probe_inode = self.probe.stat().st_ino
        real_fsync = apple_distribution.os.fsync
        mutated = False

        def mutating_fsync(descriptor: int) -> None:
            nonlocal mutated
            real_fsync(descriptor)
            if (
                not mutated
                and apple_distribution.os.fstat(descriptor).st_ino == probe_inode
            ):
                with self.probe.open("ab") as stream:
                    stream.write(b"-changed")
                mutated = True

        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            side_effect=mutating_fsync,
        ):
            with self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "file changed while it was synchronized",
            ):
                self.sync()

    def test_rejects_directory_change_during_fsync(self) -> None:
        root_inode = self.release.stat().st_ino
        real_fsync = apple_distribution.os.fsync
        mutated = False

        def mutating_fsync(descriptor: int) -> None:
            nonlocal mutated
            real_fsync(descriptor)
            state = apple_distribution.os.fstat(descriptor)
            if (
                not mutated
                and stat.S_ISDIR(state.st_mode)
                and state.st_ino == root_inode
            ):
                (self.release / "late-file").write_bytes(b"late")
                mutated = True

        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            side_effect=mutating_fsync,
        ):
            with self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "directory changed while it was synchronized",
            ):
                self.sync()

    def test_fsync_failure_is_explicit_and_cli_has_no_success_marker(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()
        with mock.patch.object(
            apple_distribution.os,
            "fsync",
            side_effect=OSError("injected fsync failure"),
        ), contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            result = apple_distribution.main(self.cli_arguments())
        self.assertEqual(result, 2)
        self.assertIn("injected fsync failure", stderr.getvalue())
        self.assertNotIn("APPLE_RELEASE_TREE_SYNC_PASS", stdout.getvalue())

    def test_full_fsync_failure_is_explicit_and_has_no_success_marker(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()
        with mock.patch.object(
            apple_distribution.sys,
            "platform",
            "darwin",
        ), mock.patch.object(
            apple_distribution.fcntl,
            "F_FULLFSYNC",
            51,
            create=True,
        ), mock.patch.object(
            apple_distribution.fcntl,
            "fcntl",
            side_effect=OSError("injected full fsync failure"),
        ), contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            result = apple_distribution.main(self.cli_arguments())
        self.assertEqual(result, 2)
        self.assertIn("injected full fsync failure", stderr.getvalue())
        self.assertNotIn("APPLE_RELEASE_TREE_SYNC_PASS", stdout.getvalue())

    def test_cli_reports_success_only_after_full_sync(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = apple_distribution.main(self.cli_arguments())
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "APPLE_RELEASE_TREE_SYNC_PASS\n")


class SubmissionStateCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.artifact = self.root / ARTIFACT_NAME
        self.artifact.write_bytes(b"command-test-zip")
        self.signing = self.root / "signing.json"
        self.signing.write_text('{"kind":"signing-test"}\n', encoding="utf-8")
        self.submit = self.root / "submit.json"
        self.submit.write_text(json.dumps({"id": SUBMISSION_ID}) + "\n", encoding="utf-8")
        self.submit_capture = self.root / "submit.partial.json"
        self.submit_capture.write_bytes(b'{"id":')
        self.prepared = self.root / "prepared.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, arguments: list[str]) -> str:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = apple_distribution.main(arguments)
        self.assertEqual(result, 0, stderr.getvalue())
        return stdout.getvalue()

    def prepare(self) -> None:
        self.invoke(
            [
                "prepared-state",
                "--artifact",
                str(self.artifact),
                "--signing-evidence",
                str(self.signing),
                "--source-commit",
                SOURCE_COMMIT,
                "--output",
                str(self.prepared),
            ]
        )

    def test_normal_and_explicit_recovery_commands_create_distinct_bound_states(self) -> None:
        self.prepare()
        normal = self.root / "normal-state.json"
        self.invoke(
            [
                "submission-state",
                "--prepared",
                str(self.prepared),
                "--artifact",
                str(self.artifact),
                "--submit",
                str(self.submit),
                "--signing-evidence",
                str(self.signing),
                "--source-commit",
                SOURCE_COMMIT,
                "--output",
                str(normal),
            ]
        )
        stdout = self.invoke(
            [
                "validate-submission-state",
                "--prepared",
                str(self.prepared),
                "--state",
                str(normal),
                "--artifact",
                str(self.artifact),
                "--signing-evidence",
                str(self.signing),
                "--submit",
                str(self.submit),
                "--submission-id",
                SUBMISSION_ID,
                "--source-commit",
                SOURCE_COMMIT,
            ]
        )
        self.assertEqual(stdout.strip(), SUBMISSION_ID)
        self.assertEqual(
            json.loads(normal.read_text(encoding="utf-8"))["submission_id_provenance"][
                "kind"
            ],
            "notarytool_submit_response",
        )
        self.assertEqual(
            self.invoke(
                ["submission-state-provenance", "--state", str(normal)]
            ).strip(),
            "notarytool_submit_response",
        )

        recovered = self.root / "recovered-state.json"
        self.invoke(
            [
                "recover-submission-state",
                "--prepared",
                str(self.prepared),
                "--artifact",
                str(self.artifact),
                "--signing-evidence",
                str(self.signing),
                "--source-commit",
                SOURCE_COMMIT,
                "--submission-id",
                SUBMISSION_ID,
                "--submit-capture",
                str(self.submit_capture),
                "--output",
                str(recovered),
            ]
        )
        stdout = self.invoke(
            [
                "validate-submission-state",
                "--prepared",
                str(self.prepared),
                "--state",
                str(recovered),
                "--artifact",
                str(self.artifact),
                "--signing-evidence",
                str(self.signing),
                "--submission-id",
                SUBMISSION_ID,
                "--submit-capture",
                str(self.submit_capture),
                "--source-commit",
                SOURCE_COMMIT,
            ]
        )
        self.assertEqual(stdout.strip(), SUBMISSION_ID)
        self.assertEqual(
            json.loads(recovered.read_text(encoding="utf-8"))[
                "submission_id_provenance"
            ]["captured_stdout"],
            {
                "size": len(self.submit_capture.read_bytes()),
                "sha256": hashlib.sha256(self.submit_capture.read_bytes()).hexdigest(),
                "parse_status": "invalid_or_truncated_json",
            },
        )
        self.assertEqual(
            self.invoke(
                ["submission-state-provenance", "--state", str(recovered)]
            ).strip(),
            "explicit_uuid_recovery",
        )

    def test_recovery_command_rejects_complete_valid_submit_capture(self) -> None:
        self.prepare()
        self.submit_capture.write_text(
            json.dumps({"id": SUBMISSION_ID}) + "\n",
            encoding="utf-8",
        )
        output = self.root / "must-not-exist.json"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = apple_distribution.main(
                [
                    "recover-submission-state",
                    "--prepared",
                    str(self.prepared),
                    "--artifact",
                    str(self.artifact),
                    "--signing-evidence",
                    str(self.signing),
                    "--source-commit",
                    SOURCE_COMMIT,
                    "--submission-id",
                    SUBMISSION_ID,
                    "--submit-capture",
                    str(self.submit_capture),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("use the normal submit-response path", stderr.getvalue())
        self.assertFalse(output.exists())


class XCFrameworkZipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.archive = self.root / ARTIFACT_NAME

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_archive(self, *, signed: bool = True, unsafe_symlink: bool = False) -> None:
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("CQPeriapt.xcframework/Info.plist", b"plist")
            for library in sorted(apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES):
                archive.writestr(f"CQPeriapt.xcframework/{library}", b"static-library")
            if signed:
                archive.writestr(
                    "CQPeriapt.xcframework/_CodeSignature/CodeResources",
                    b"sealed-resources",
                )
            if unsafe_symlink:
                info = zipfile.ZipInfo("CQPeriapt.xcframework/escape")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, "../../outside")

    def test_accepts_exact_signed_archive(self) -> None:
        self.write_archive()
        apple_distribution.validate_xcframework_zip(
            self.archive,
            require_signature=True,
        )

    def test_rejects_missing_signature_resources(self) -> None:
        self.write_archive(signed=False)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "lacks required entries",
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive,
                require_signature=True,
            )

    def test_rejects_symlink_entry_before_extraction(self) -> None:
        self.write_archive(unsafe_symlink=True)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "unsupported XCFramework ZIP entry type",
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive,
                require_signature=True,
            )


class ReleaseWorkflowSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = pathlib.Path(__file__).resolve().parents[1]
        cls.builder = (cls.root / "artifact/swift-xcframework.sh").read_text(
            encoding="utf-8"
        )
        cls.release = (cls.root / "artifact/swift-xcframework-release.sh").read_text(
            encoding="utf-8"
        )
        cls.remote = (
            cls.root / "artifact/swift-xcframework-remote-consumer.sh"
        ).read_text(encoding="utf-8")
        cls.consumer_check = (
            cls.root / "artifact/swift-xcframework-consumer-check.sh"
        ).read_text(encoding="utf-8")

    def test_credentialed_mode_has_a_separate_explicit_entrypoint(self) -> None:
        self.assertIn("swift-xcframework-release-v1", self.builder)
        self.assertIn("QPERIAPT_APPLE_RELEASE_CONFIRM", self.release)
        self.assertIn("credentialed Apple distribution requires a clean worktree", self.release)
        self.assertIn("git worktree add --detach", self.release)
        self.assertIn("QPERIAPT_INTERNAL_APPLE_SOURCE_COMMIT", self.release)

    def test_signing_identity_and_certificate_are_exactly_pinned(self) -> None:
        self.assertIn("2DA7764ED42B213AE04925B6261238B24C758FE1", self.release)
        self.assertIn(
            "806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D",
            self.release,
        )
        self.assertIn('EXPECTED_TEAM_ID="YKUPL7Z869"', self.release)

    def test_workflow_has_no_unsafe_signing_or_credential_fallbacks(self) -> None:
        source = self.builder + self.release
        for forbidden in (
            "--deep",
            "--force",
            "--timestamp=none",
            "--password",
            "--apple-id",
            "dump-keychain",
            "netdiag-notary",
            "set -x",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("codesign --timestamp", self.builder)
        self.assertIn("notarytool submit", self.builder)
        self.assertIn("notarytool wait", self.builder)
        self.assertIn("notarytool info", self.builder)
        self.assertIn("notarytool log", self.builder)

    def test_public_evidence_never_records_keychain_profile(self) -> None:
        public_projection = {
            "kind": "qperiapt.apple_notarization",
            "signer": {"team_id": "YKUPL7Z869"},
            "submission": {"id": SUBMISSION_ID},
        }
        serialized = json.dumps(public_projection, sort_keys=True)
        self.assertNotIn("private-notary-profile", serialized)
        self.assertNotIn("keychain", serialized.lower())
        self.assertIn("unset NOTARY_KEYCHAIN_PROFILE", self.release)
        self.assertIn(
            "NOTARY_KEYCHAIN_PROFILE=${QPERIAPT_NOTARY_KEYCHAIN_PROFILE:-}",
            self.release,
        )
        self.assertIn("unset QPERIAPT_NOTARY_KEYCHAIN_PROFILE", self.release)
        self.assertIn(
            "NOTARY_KEYCHAIN_PROFILE=${QPERIAPT_INTERNAL_NOTARY_KEYCHAIN_PROFILE:-}",
            self.builder,
        )
        self.assertIn("unset QPERIAPT_INTERNAL_NOTARY_KEYCHAIN_PROFILE", self.builder)

    def test_keychain_profile_is_deexported_before_python_bootstrap(self) -> None:
        scripts = (
            (
                self.release,
                "QPERIAPT_NOTARY_KEYCHAIN_PROFILE",
                "outer-private-profile",
            ),
            (
                self.builder,
                "QPERIAPT_INTERNAL_NOTARY_KEYCHAIN_PROFILE",
                "inner-private-profile",
            ),
        )
        source_line = '. "$ROOT/artifact/python-env.sh"'
        for source, input_name, secret in scripts:
            with self.subTest(input_name=input_name), tempfile.TemporaryDirectory() as raw:
                capture_position = source.index(
                    f"NOTARY_KEYCHAIN_PROFILE=${{{input_name}:-}}"
                )
                input_unset_position = source.index(f"unset {input_name}")
                first_external_position = source.index('ROOT=$(cd -- "$(dirname "$0")/.."')
                self.assertLess(capture_position, first_external_position)
                self.assertLess(input_unset_position, first_external_position)
                root = pathlib.Path(raw)
                artifact = root / "artifact"
                artifact.mkdir()
                prefix = source.split(source_line, 1)[0]
                (artifact / "profile-prefix.sh").write_text(
                    prefix + source_line + "\n",
                    encoding="utf-8",
                )
                (artifact / "python-env.sh").write_text(
                    'env >"$PROFILE_ENV_CAPTURE"\n',
                    encoding="utf-8",
                )
                capture = root / "child.env"
                environment = os.environ.copy()
                environment.update(
                    {
                        input_name: secret,
                        "NOTARY_KEYCHAIN_PROFILE": "ambient-exported-profile",
                        "PROFILE_ENV_CAPTURE": str(capture),
                    }
                )
                completed = subprocess.run(
                    ["/bin/sh", str(artifact / "profile-prefix.sh")],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                child_environment = capture.read_text(encoding="utf-8")
                self.assertNotIn(input_name + "=", child_environment)
                self.assertNotIn("NOTARY_KEYCHAIN_PROFILE=", child_environment)
                self.assertNotIn(secret, child_environment)
                self.assertNotIn("ambient-exported-profile", child_environment)

    def test_release_status_checks_cannot_refresh_git_indexes(self) -> None:
        for source_name, source in (
            ("builder", self.builder),
            ("release", self.release),
        ):
            self.assertIn("/usr/bin/env -i", source)
            self.assertIn("GIT_OPTIONAL_LOCKS=0", source)
            status_lines = [
                line for line in source.splitlines() if " status --porcelain" in line
            ]
            self.assertTrue(status_lines, source_name)
            for line in status_lines:
                with self.subTest(source_name=source_name, line=line):
                    self.assertRegex(
                        line,
                        r"release_(?:git|main_git|worktree_git) status --porcelain",
                    )
        self.assertNotIn('["git", "status"', self.builder)
        self.assertIn('git_dirty = bool(\n    run_git(', self.builder)

    def test_git_repository_environment_overrides_fail_before_external_commands(self) -> None:
        override_names = (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_SHALLOW_FILE",
            "GIT_NAMESPACE",
            "GIT_REPLACE_REF_BASE",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        )
        script_paths = (
            self.root / "artifact/swift-xcframework.sh",
            self.root / "artifact/swift-xcframework-release.sh",
        )
        base_environment = os.environ.copy()
        for name in override_names:
            base_environment.pop(name, None)
        for script_path in script_paths:
            source = script_path.read_text(encoding="utf-8")
            for name in override_names:
                with self.subTest(script=script_path.name, name=name):
                    self.assertIn(f'${{{name}+x}}', source)
                    environment = base_environment.copy()
                    environment[name] = ""
                    completed = subprocess.run(
                        ["/bin/sh", str(script_path)],
                        cwd=self.root,
                        env=environment,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertIn(
                        "rejects Git repository/configuration environment overrides",
                        completed.stderr,
                    )

    def test_resume_validation_cannot_sign_zip_or_submit(self) -> None:
        resume = self.builder.split("# BEGIN_NOTARY_RESUME_VALIDATION", 1)[1].split(
            "# END_NOTARY_RESUME_VALIDATION", 1
        )[0]
        for forbidden in ("codesign --sign", "zip -q", "notarytool submit", "rm -rf \"$OUT_ROOT\""):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, resume)
        self.assertIn("validate-submission-state", resume)
        self.assertIn("cmp \"$SIGNING_EVIDENCE\" \"$RESUME_SIGNING_EVIDENCE\"", resume)

    def test_resume_mode_is_selected_before_output_cleanup(self) -> None:
        selector = self.builder.index('if [ -z "$RESUME_SUBMISSION_ID" ]; then')
        destructive_cleanup = self.builder.index('rm -rf "$OUT_ROOT"')
        self.assertLess(selector, destructive_cleanup)

    def test_notary_attempt_is_durably_prepared_before_the_only_submit(self) -> None:
        notarization = self.builder.split("=== Apple notarization ===", 1)[1]
        sync_tree = notarization.index("apple_distribution.py sync-release-tree")
        ledger_directory = notarization.index('mkdir "$NOTARY_WORK"', sync_tree)
        prepared = notarization.index("apple_distribution.py prepared-state", sync_tree)
        capture = notarization.index("apple_distribution.py prepare-submit-capture", sync_tree)
        trap = notarization.index("install_notary_release_traps", sync_tree)
        submit = notarization.index("notarytool submit", sync_tree)
        finalized = notarization.index(
            "apple_distribution.py finalize-submit-capture", sync_tree
        )
        self.assertEqual(self.builder.count("sync-release-tree"), 1)
        self.assertLess(sync_tree, ledger_directory)
        self.assertLess(ledger_directory, prepared)
        self.assertLess(prepared, capture)
        self.assertLess(capture, trap)
        self.assertLess(trap, submit)
        self.assertLess(submit, finalized)
        self.assertEqual(notarization.count("xcrun notarytool submit"), 1)
        self.assertIn('--output-format json >>"$SUBMIT_CAPTURE"', notarization)
        self.assertIn("never submit this artifact again", notarization)
        self.assertIn("submission-state-provenance", self.builder)
        self.assertIn("recover-submission-state", self.builder)

    def test_notary_signal_traps_cannot_report_success(self) -> None:
        trap_functions = self.builder.split("# BEGIN_NOTARY_TRAP_FUNCTIONS", 1)[1].split(
            "# END_NOTARY_TRAP_FUNCTIONS", 1
        )[0]
        self.assertIn("trap 'notary_release_signal 130' INT", self.builder)
        self.assertIn("trap 'notary_release_signal 143' TERM", self.builder)
        for signal, expected_status in (("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal):
                harness = f"""set -eu
old_umask=$(umask)
tmp_header=
NOTARY_COMPLETE=0
NOTARY_ATTEMPT_PREPARED=1
ACTIVE_SUBMISSION_ID=
{trap_functions}
install_notary_release_traps
kill -{signal} $$
exit 0
"""
                completed = subprocess.run(
                    ["/bin/sh", "-c", harness],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, expected_status)
                self.assertIn("never submit this artifact again", completed.stderr)

    def test_build_signal_traps_cannot_report_success(self) -> None:
        trap_functions = self.builder.split("# BEGIN_BUILD_TRAP_FUNCTIONS", 1)[1].split(
            "# END_BUILD_TRAP_FUNCTIONS", 1
        )[0]
        self.assertIn("trap 'cleanup_signal 130' INT", self.builder)
        self.assertIn("trap 'cleanup_signal 143' TERM", self.builder)
        for signal, expected_status in (("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal), tempfile.TemporaryDirectory() as temporary:
                sentinel = pathlib.Path(temporary) / "temporary-header.h"
                sentinel.write_bytes(b"temporary")
                harness = f"""set -eu
tmp_header=$1
{trap_functions}
trap cleanup EXIT
trap 'cleanup_signal 130' INT
trap 'cleanup_signal 143' TERM
kill -{signal} $$
exit 0
"""
                completed = subprocess.run(
                    ["/bin/sh", "-c", harness, "build-trap-test", str(sentinel)],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, expected_status)
                self.assertFalse(sentinel.exists())

    def test_notary_ledger_is_outside_disposable_build_output(self) -> None:
        self.assertIn(
            'NOTARY_STATE_ROOT="$WORKTREE_ROOT/target/qperiapt-apple-notary-state"',
            self.release,
        )
        self.assertIn("QPERIAPT_INTERNAL_NOTARY_STATE_DIR", self.release)
        self.assertIn(
            "durable notary state must be outside the disposable build output",
            self.builder,
        )
        worktree = self.root / "target/qperiapt-apple-release-worktrees" / ("a" * 40) / "source"
        detached_target = worktree / "target"
        state = detached_target / "qperiapt-apple-notary-state"
        disposable_output = detached_target / "qperiapt-swift-xcframework"
        self.assertTrue(state.is_relative_to(detached_target))
        self.assertFalse(state.is_relative_to(disposable_output))

    def test_release_worktree_identity_and_private_root_are_fail_closed(self) -> None:
        self.assertIn("release_git rev-parse --show-toplevel", self.builder)
        self.assertIn("--path-format=absolute --git-common-dir", self.builder)
        self.assertIn('current_toplevel" != "$ROOT', self.builder)
        self.assertIn("release_worktree_git rev-parse --show-toplevel", self.release)
        self.assertIn("release_worktree_git rev-parse --absolute-git-dir", self.release)
        self.assertIn('WORKTREE_TOPLEVEL" != "$WORKTREE_ROOT', self.release)
        self.assertIn('WORKTREE_COMMON_GIT_DIR" != "$ROOT/.git', self.release)
        self.assertIn('chmod 700 "$RELEASE_ROOT"', self.release)
        self.assertIn("stat.S_IMODE(state.st_mode) != 0o700", self.release)
        self.assertIn("QPERIAPT_INTERNAL_APPLE_DURABILITY_ROOT", self.release)

    def test_wrapper_pins_and_reverifies_the_public_copy(self) -> None:
        self.assertIn(
            'QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR="$SOURCE_OUT"', self.release
        )
        for release_file in (
            "CQPeriapt.xcframework.zip",
            "NOTARIZATION.json",
            "MANIFEST.json",
            "SHA256SUMS",
        ):
            with self.subTest(release_file=release_file):
                self.assertIn(release_file, self.release)
        self.assertGreaterEqual(self.release.count("shasum -c SHA256SUMS"), 2)
        self.assertIn('cmp "$SOURCE_DIST/$release_file" "$PUBLIC_DIST/$release_file"', self.release)
        self.assertIn(
            'codesign --verify --strict --verbose=4 "$PUBLIC_DIST/CQPeriapt.xcframework"',
            self.release,
        )

    def test_remote_consumer_is_pinned_and_reverifies_public_bytes(self) -> None:
        self.assertIn(
            'EXPECTED_URL="https://github.com/billlza/q-periapt/releases/download/v$VERSION/CQPeriapt.xcframework.zip"',
            self.remote,
        )
        self.assertIn('if [ "$URL" != "$EXPECTED_URL" ]', self.remote)
        self.assertIn('swift package compute-checksum "$REMOTE_ZIP"', self.remote)
        self.assertIn('codesign --verify --strict --verbose=4', self.remote)
        self.assertIn('WORKTREE_COMMIT=$(git -C "$SOURCE_WORKTREE" rev-parse HEAD)', self.remote)
        self.assertIn('WORKTREE_STATUS=$(git -C "$SOURCE_WORKTREE" status', self.remote)
        self.assertIn('git -C "$SOURCE_WORKTREE" ls-files --error-unmatch', self.remote)
        self.assertNotIn("SOURCE_CONSUMER", self.remote)
        for fixture in (
            "bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift",
            "bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift",
            "bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift",
            "bindings/signed-policy-vectors.json",
        ):
            with self.subTest(fixture=fixture):
                self.assertIn(fixture, self.builder)
                self.assertIn(fixture, self.remote)
        self.assertIn('.binaryTarget(', self.remote)
        self.assertNotIn("--insecure", self.remote)

    def test_apple_consumers_perform_final_links_and_macos_runtime(self) -> None:
        self.assertIn("QPeriaptLinkProbe", self.builder)
        self.assertIn("QPeriaptLinkProbe", self.remote)
        self.assertIn("need swift", self.consumer_check)
        for scoped_function in (
            "validate_probe() (",
            "run_macos_link_gate() (",
            "run_ios_link_gate() (",
        ):
            with self.subTest(scoped_function=scoped_function):
                self.assertIn(scoped_function, self.consumer_check)
        self.assertIn("--triple \"$triple\"", self.consumer_check)
        self.assertIn('triple="${arch}-apple-macosx13.0"', self.consumer_check)
        self.assertNotIn("generic/platform=macOS'", self.consumer_check)
        self.assertIn("generic/platform=iOS'", self.consumer_check)
        self.assertIn("generic/platform=iOS Simulator'", self.consumer_check)
        self.assertIn("ProcessXCFramework", self.consumer_check)
        self.assertIn("-lq_periapt_ffi_abi2", self.consumer_check)
        self.assertIn('cmp "$expected" "$processed"', self.consumer_check)
        self.assertIn('nm -u "$probe"', self.consumer_check)
        self.assertIn("vtool -show-build", self.consumer_check)
        self.assertIn('arch "-$arch" "$probe"', self.consumer_check)
        self.assertIn("SWIFT_XCFRAMEWORK_MACOS_RUNTIME_PASS", self.consumer_check)
        self.assertIn(
            'QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME="$APPLE_RELEASE_MODE"',
            self.builder,
        )
        self.assertIn("QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME=0", self.remote)
        self.assertNotIn("LM_FILTER_WARNINGS", self.consumer_check)
        self.assertNotIn("skipPackagePluginValidation", self.consumer_check)


if __name__ == "__main__":
    unittest.main()
