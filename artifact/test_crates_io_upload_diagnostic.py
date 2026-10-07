"""Safe logging rejects arbitrary child output without hiding its failure."""

from __future__ import annotations

import json
import unittest

from crates_io_upload_diagnostic import (
    MAX_DIAGNOSTIC_BYTES,
    UploadCategory,
    UploadDiagnosticError,
    UploadStage,
    parse_upload_diagnostic,
    validate_upload_diagnostic_document,
)


TOKEN = "cioDiagnosticTestCredential0123456789"


class UploadDiagnosticTests(unittest.TestCase):
    def document(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "stage": "response_body",
            "category": "response",
            "http_status": 429,
            "sent_body_bytes_lower_bound": 4_959_905,
            "elapsed_ms": 1234,
            "retry_after_seconds": 60,
        }

    def parse(self, value: dict[str, object], *, returncode: int = 1):
        return parse_upload_diagnostic(
            (json.dumps(value) + "\n").encode(),
            credential=TOKEN,
            returncode=returncode,
        )

    def test_http_failure_preserves_safe_actionable_fields(self):
        value = self.document()
        diagnostic = self.parse(value)
        self.assertEqual(diagnostic.stage, UploadStage.RESPONSE_BODY)
        self.assertEqual(diagnostic.category, UploadCategory.RESPONSE)
        self.assertEqual(diagnostic.to_document(), value)

    def test_transport_failure_has_no_invented_http_status(self):
        value = self.document()
        value.update(stage="archive", category="connection", http_status=None,
                     retry_after_seconds=None)
        diagnostic = self.parse(value)
        self.assertIsNone(diagnostic.http_status)
        self.assertEqual(diagnostic.sent_body_bytes_lower_bound, 4_959_905)

    def test_stored_document_revalidation_needs_no_credential(self):
        value = self.document()
        diagnostic = validate_upload_diagnostic_document(value, returncode=1)
        self.assertEqual(diagnostic.to_document(), value)
        for invalid in (None, [], value | {"category": TOKEN}, value | {"body": TOKEN}):
            with self.subTest(value_type=type(invalid).__name__):
                with self.assertRaises(UploadDiagnosticError) as raised:
                    validate_upload_diagnostic_document(invalid, returncode=1)
                self.assertNotIn(TOKEN, str(raised.exception))

    def test_success_requires_process_and_http_acceptance(self):
        value = self.document()
        value.update(stage="complete", category="ok", http_status=200,
                     retry_after_seconds=None)
        self.assertEqual(self.parse(value, returncode=0).category, UploadCategory.OK)
        for changes, status in (({}, 1), ({"http_status": 503}, 0),
                                ({"http_status": None}, 0),
                                ({"stage": "cleanup"}, 0),
                                ({"category": "internal"}, 0)):
            with self.subTest(changes=changes, status=status):
                with self.assertRaises(UploadDiagnosticError):
                    self.parse(value | changes, returncode=status)

    def test_rejects_unsupported_or_unbounded_fields(self):
        for changes in (
            {"schema_version": True}, {"schema_version": 2},
            {"stage": "new-stage"}, {"category": "new-error"},
            {"http_status": True}, {"http_status": 600},
            {"sent_body_bytes_lower_bound": -1},
            {"sent_body_bytes_lower_bound": 150_994_953},
            {"elapsed_ms": 1.5}, {"elapsed_ms": 2**63},
            {"retry_after_seconds": -1}, {"retry_after_seconds": 86_401},
            {"body": "server-controlled response"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(UploadDiagnosticError):
                    self.parse(self.document() | changes)
        missing = self.document()
        del missing["http_status"]
        with self.assertRaises(UploadDiagnosticError):
            self.parse(missing)

    def test_raw_or_duplicate_json_is_never_reported(self):
        encoded = json.dumps(self.document()).encode()
        for output in (
            b"", encoded, encoded + b"\n\n", encoded + b"\r\n",
            b"x" * (MAX_DIAGNOSTIC_BYTES + 1) + b"\n",
            b'{"schema_version":1,"schema_version":1}\n',
            b"\xff\n", b"null\n", b"NaN\n",
        ):
            with self.subTest(length=len(output)):
                with self.assertRaises(UploadDiagnosticError):
                    parse_upload_diagnostic(output, credential=TOKEN, returncode=1)

    def test_credential_and_arbitrary_text_do_not_enter_errors(self):
        for value in (
            self.document() | {"category": TOKEN},
            self.document() | {"stage": "untrusted-server-secret"},
            self.document() | {"body": TOKEN},
        ):
            with self.assertRaises(UploadDiagnosticError) as raised:
                self.parse(value)
            self.assertNotIn(TOKEN, str(raised.exception))
            self.assertNotIn("untrusted-server-secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
