"""Parse the uploader's bounded, secret-free transport diagnostic.

These fields describe one client attempt, never registry publication authority.
Only the independent API and sparse-index observations establish publication.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from evidence_io import EvidenceIOError, parse_strict_json_bytes


MAX_DIAGNOSTIC_BYTES = 4096
MAX_SENT_BODY_BYTES = 150_994_952
MAX_ELAPSED_MS = 9_223_372_036_854_775_807


class UploadDiagnosticError(ValueError):
    """The uploader did not return its safe diagnostic contract."""


class UploadStage(str, Enum):
    PREFLIGHT = "preflight"
    CONNECT = "connect"
    HEADERS = "headers"
    METADATA = "metadata"
    ARCHIVE = "archive"
    RESPONSE_HEADERS = "response_headers"
    RESPONSE_BODY = "response_body"
    CLEANUP = "cleanup"
    COMPLETE = "complete"


class UploadCategory(str, Enum):
    OK = "ok"
    PROTOCOL = "protocol"
    ENVIRONMENT = "environment"
    CREDENTIAL = "credential"
    INPUT = "input"
    ENDPOINT = "endpoint"
    TIMEOUT = "timeout"
    DNS = "dns"
    TLS = "tls"
    CONNECTION = "connection"
    HTTP_PROTOCOL = "http_protocol"
    TRANSPORT = "transport"
    REDIRECT = "redirect"
    RESPONSE = "response"
    INTERNAL = "internal"


@dataclass(frozen=True)
class UploadDiagnostic:
    stage: UploadStage
    category: UploadCategory
    http_status: int | None
    sent_body_bytes_lower_bound: int
    elapsed_ms: int
    retry_after_seconds: int | None

    def to_document(self) -> dict[str, object]:
        """Return only validated protocol fields, suitable for operator logs."""

        return {
            "schema_version": 1,
            "stage": self.stage.value,
            "category": self.category.value,
            "http_status": self.http_status,
            "sent_body_bytes_lower_bound": self.sent_body_bytes_lower_bound,
            "elapsed_ms": self.elapsed_ms,
            "retry_after_seconds": self.retry_after_seconds,
        }


def _integer(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise UploadDiagnosticError("uploader diagnostic integer is invalid")
    return value


def parse_upload_diagnostic(
    output: bytes, *, credential: str, returncode: int
) -> UploadDiagnostic:
    """Reject raw output, unknown fields, and inconsistent process outcomes.

    Failure messages deliberately contain no child-controlled data.  The caller
    must still reconcile remotely after a missing or invalid diagnostic.
    """

    if (
        type(output) is not bytes
        or not 0 < len(output) <= MAX_DIAGNOSTIC_BYTES
        or not output.endswith(b"\n")
        or output.count(b"\n") != 1
        or b"\r" in output
    ):
        raise UploadDiagnosticError("uploader diagnostic framing is invalid")
    if not isinstance(credential, str) or not credential:
        raise UploadDiagnosticError("uploader diagnostic credential guard is invalid")
    if credential.encode("utf-8") in output:
        raise UploadDiagnosticError("uploader diagnostic contains a credential")
    try:
        document = parse_strict_json_bytes(output, label="uploader diagnostic")
    except EvidenceIOError:
        raise UploadDiagnosticError("uploader diagnostic JSON is invalid") from None
    return validate_upload_diagnostic_document(document, returncode=returncode)


def validate_upload_diagnostic_document(
    document: object, *, returncode: int
) -> UploadDiagnostic:
    """Revalidate stored safe fields without requiring a past credential."""

    if type(returncode) is not int:
        raise UploadDiagnosticError("uploader diagnostic process status is invalid")
    expected_keys = {
        "schema_version", "stage", "category", "http_status",
        "sent_body_bytes_lower_bound", "elapsed_ms", "retry_after_seconds",
    }
    if type(document) is not dict or set(document) != expected_keys:
        raise UploadDiagnosticError("uploader diagnostic fields differ")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise UploadDiagnosticError("uploader diagnostic schema is unsupported")
    if type(document["stage"]) is not str or type(document["category"]) is not str:
        raise UploadDiagnosticError("uploader diagnostic classification is invalid")
    try:
        stage = UploadStage(document["stage"])
        category = UploadCategory(document["category"])
    except ValueError:
        raise UploadDiagnosticError("uploader diagnostic classification is invalid") from None
    status = document["http_status"]
    if status is not None:
        status = _integer(status, minimum=100, maximum=599)
    sent = _integer(document["sent_body_bytes_lower_bound"], minimum=0, maximum=MAX_SENT_BODY_BYTES)
    elapsed = _integer(document["elapsed_ms"], minimum=0, maximum=MAX_ELAPSED_MS)
    retry_after = document["retry_after_seconds"]
    if retry_after is not None:
        retry_after = _integer(retry_after, minimum=0, maximum=86_400)
    success = category is UploadCategory.OK
    if success != (returncode == 0) or success != (stage is UploadStage.COMPLETE):
        raise UploadDiagnosticError("uploader diagnostic outcome differs from process status")
    if success and (status is None or not 200 <= status <= 299):
        raise UploadDiagnosticError("uploader diagnostic success lacks an accepted HTTP status")
    return UploadDiagnostic(stage, category, status, sent, elapsed, retry_after)
