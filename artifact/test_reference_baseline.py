from __future__ import annotations

import hashlib
import http.client
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from reference_baseline import (
    BaselineError,
    RAW_SHA256,
    SIGNAL_CFEMAIL_SHA256,
    fetch,
    find_component,
    load_baseline,
    normalize_content,
    verify_content,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "continuity" / "reference-baseline.json"


class ReferenceBaselineTests(unittest.TestCase):
    def test_repository_baseline_has_unique_schema_v3_components(self) -> None:
        baseline = load_baseline(BASELINE)
        self.assertEqual(baseline["schema_version"], 3)
        self.assertEqual(find_component(baseline, "PQXDH")["id"], "PQXDH")

    def test_signal_cfemail_randomization_normalizes_deterministically(self) -> None:
        component = {
            "id": "SIGNAL-TEST",
            "url": "https://signal.org/example/",
            "content_hash": {"method": SIGNAL_CFEMAIL_SHA256, "sha256": "0" * 64},
        }
        first = (
            b'<span data-cfemail="001122">x</span>'
            b'/cdn-cgi/l/email-protection#abcdef'
        )
        second = (
            b'<span data-cfemail="ffeeddccbbaa">x</span>'
            b'/cdn-cgi/l/email-protection#1234567890'
        )
        self.assertNotEqual(first, second)
        self.assertEqual(normalize_content(component, first), normalize_content(component, second))

    def test_verify_content_accepts_declared_normalized_hash(self) -> None:
        content = b'<span data-cfemail="001122">x</span>'
        component = {
            "id": "SIGNAL-TEST",
            "url": "https://signal.org/example/",
            "content_hash": {
                "method": SIGNAL_CFEMAIL_SHA256,
                "sha256": hashlib.sha256(b'<span data-cfemail="<normalized>">x</span>').hexdigest(),
            },
        }
        self.assertEqual(verify_content(component, content)[0], SIGNAL_CFEMAIL_SHA256)

    def test_raw_hash_rejects_changed_bytes(self) -> None:
        component = {
            "id": "RAW-TEST",
            "url": "https://example.com/reference.txt",
            "content_hash": {
                "method": RAW_SHA256,
                "sha256": hashlib.sha256(b"expected").hexdigest(),
            },
        }
        with self.assertRaisesRegex(BaselineError, "content hash mismatch"):
            verify_content(component, b"changed")

    def test_loader_rejects_duplicate_component_ids(self) -> None:
        data = {"schema_version": 3, "components": [{"id": "A"}, {"id": "A"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "unique"):
                load_baseline(path)

    def test_incomplete_http_body_is_wrapped_as_baseline_error(self) -> None:
        class IncompleteResponse:
            def __enter__(self) -> "IncompleteResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _limit: int) -> bytes:
                raise http.client.IncompleteRead(b"partial", 8)

        with mock.patch(
            "reference_baseline.urllib.request.urlopen",
            return_value=IncompleteResponse(),
        ):
            with self.assertRaisesRegex(BaselineError, "cannot retrieve"):
                fetch("https://signal.org/example/", 1.0)


if __name__ == "__main__":
    unittest.main()
