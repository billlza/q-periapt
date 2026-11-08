from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

import codeql_log_recovery as recovery


class LogRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def archive(self, entries: dict[str, bytes]) -> Path:
        path = self.root / "diagnostics.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, data in entries.items():
                output.writestr(name, data)
        return path

    @contextlib.contextmanager
    def admitted(self, data: bytes):
        with (
            mock.patch.object(recovery, "ARCHIVE_BYTES", len(data)),
            mock.patch.object(recovery, "ARCHIVE_SHA256", hashlib.sha256(data).hexdigest()),
        ):
            yield

    def test_download_uses_fixed_api_and_never_forwards_bearer_token(self) -> None:
        payload = b"exact retained payload"
        signed = "https://example.blob.core.windows.net/artifact?sig=private-url"
        redirect = urllib.error.HTTPError("https://api.github.com", 302, "Found", {"Location": signed}, None)
        opener = mock.Mock()
        opener.open.side_effect = [redirect, io.BytesIO(payload)]
        output = self.root / "download.zip"
        with (
            self.admitted(payload),
            mock.patch.dict(os.environ, GH_TOKEN="private-bearer"),
            mock.patch.object(recovery.urllib.request, "build_opener", return_value=opener),
        ):
            recovery.download(output)
        first, second = opener.open.call_args_list
        self.assertEqual(first.args[0].full_url,
                         f"https://api.github.com/repos/billlza/q-periapt/actions/artifacts/{recovery.ARTIFACT_ID}/zip")
        self.assertEqual(first.args[0].get_header("Authorization"), "Bearer private-bearer")
        self.assertEqual(second.args, (signed,))
        self.assertEqual(second.kwargs, {"timeout": 45})
        self.assertEqual(output.read_bytes(), payload)

    def test_download_rejects_non_https_or_credential_bearing_redirect(self) -> None:
        for target in ("http://example.test/a", "https://user:password@example.test/a", ""):
            with self.subTest(target=target):
                redirect = urllib.error.HTTPError("https://api.github.com", 302, "Found", {"Location": target}, None)
                opener = mock.Mock()
                opener.open.side_effect = redirect
                with (
                    mock.patch.dict(os.environ, GH_TOKEN="private-bearer"),
                    mock.patch.object(recovery.urllib.request, "build_opener", return_value=opener),
                    self.assertRaises(recovery.RecoveryError),
                ):
                    recovery.download(self.root / "download.zip")
                self.assertEqual(opener.open.call_count, 1)

    def test_transfer_rejects_oversized_truncated_changed_or_expired_payload(self) -> None:
        payload = b"fixed bytes"
        with self.admitted(payload), mock.patch.object(recovery.time, "monotonic", return_value=1):
            for actual, deadline in ((payload + b"x", 2), (payload[:-1], 2), (b"other bytes", 2), (payload, 0)):
                with self.subTest(actual=actual, deadline=deadline), self.assertRaises(recovery.RecoveryError):
                    recovery.copy_download(io.BytesIO(actual), io.BytesIO(), deadline=deadline)

    def test_member_admission_rejects_escape_alias_link_and_encoding(self) -> None:
        for name in ("../outside", "/outside", "a/../../outside", "a\\outside", "a//b", "a/./b", "a\0b"):
            with self.subTest(name=name), self.assertRaises(recovery.RecoveryError):
                recovery.safe_member(zipfile.ZipInfo(name))
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
            member = zipfile.ZipInfo("log")
            member.external_attr = (mode | 0o600) << 16
            with self.subTest(mode=mode), self.assertRaises(recovery.RecoveryError):
                recovery.safe_member(member)
        encrypted = zipfile.ZipInfo("encrypted")
        encrypted.flag_bits = 1
        with self.assertRaises(recovery.RecoveryError):
            recovery.safe_member(encrypted)

    def test_member_admission_rejects_duplicate_and_excessive_inventory(self) -> None:
        member = zipfile.ZipInfo(recovery.LOG_PREFIX + "query.log")
        for members in ([member, member], [member] * (recovery.MAX_MEMBERS + 1)):
            with self.subTest(count=len(members)), self.assertRaises(recovery.RecoveryError):
                recovery.select_logs(mock.Mock(infolist=lambda: members))

    def test_wrong_archive_identity_is_rejected_before_any_log_is_written(self) -> None:
        path = self.archive({recovery.LOG_PREFIX + "query.log": b"original\n"})
        original = path.read_bytes()
        with self.admitted(original):
            path.write_bytes(original + b"x")
            with self.assertRaisesRegex(recovery.RecoveryError, "SHA-256 differs"):
                recovery.recover_logs(path, self.evidence)
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            with self.assertRaisesRegex(recovery.RecoveryError, "SHA-256 differs"):
                recovery.recover_logs(path, self.evidence)
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_only_logs_are_read_and_complete_bytes_survive_gzip_recovery(self) -> None:
        log = (
            b"[2026-11-08 00:00:00] [PROGRESS] execute queries> Starting evaluation of summary/SummaryStats.ql.\n"
            b"[2026-11-08 00:00:01] [PROGRESS] execute queries> [38/39 eval 7.4s] Evaluation done; writing results to summary/Other.bqrs.\n"
            b"[2026-11-08 00:00:02] Starting to evaluate predicate TaintReach::Flow::Stage3::fwd/4 (iteration 444)\n"
            b"[2026-11-08 00:00:03] Pausing evaluation to evict 209.99MiB ARRAYS\n"
        )
        member = recovery.LOG_PREFIX + "execute-queries.log"
        path = self.archive({member: log, "qperiapt-codeql-wasm/diagnostics/database.zip": b"not an inner ZIP"})
        real_open = zipfile.ZipFile.open
        opened = []

        def log_only(archive, selected, *args, **kwargs):
            name = selected.filename if isinstance(selected, zipfile.ZipInfo) else selected
            self.assertEqual(name, member)
            opened.append(name)
            return real_open(archive, selected, *args, **kwargs)

        with self.admitted(path.read_bytes()), mock.patch.object(zipfile.ZipFile, "open", log_only):
            rows = recovery.recover_logs(path, self.evidence)
        self.assertEqual(opened, [member])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(gzip.decompress((self.evidence / row["gzip"]).read_bytes()), log)
        self.assertEqual((row["bytes"], row["sha256"]), (len(log), hashlib.sha256(log).hexdigest()))
        summary = row["summary"]
        self.assertEqual((summary["lines"], summary["query_starts"], summary["query_completions"]), (4, 1, 1))
        self.assertEqual(summary["max_taint_stage_iterations"], {"3": 444})
        self.assertEqual(summary["cache_eviction_pauses"], 1)
        self.assertEqual(json.loads((self.evidence / "LOGS.json").read_text()), rows)

    def test_missing_or_oversized_logs_are_rejected_before_extraction(self) -> None:
        path = self.archive({"qperiapt-codeql-wasm/diagnostics/database.zip": b"database"})
        with self.admitted(path.read_bytes()), self.assertRaisesRegex(recovery.RecoveryError, "census"):
            recovery.recover_logs(path, self.evidence)
        path = self.archive({recovery.LOG_PREFIX + "query.log": b"too large\n"})
        for limit in ("MAX_LOG_FILE_BYTES", "MAX_TOTAL_LOG_BYTES"):
            with (
                self.subTest(limit=limit), self.admitted(path.read_bytes()),
                mock.patch.object(recovery, limit, 1),
                self.assertRaisesRegex(recovery.RecoveryError, "uncompressed bound"),
            ):
                recovery.recover_logs(path, self.evidence)
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_compressed_output_overflow_does_not_publish_partial_gzip(self) -> None:
        path = self.archive({recovery.LOG_PREFIX + "query.log": b"bounded log\n"})
        with (
            self.admitted(path.read_bytes()),
            mock.patch.object(recovery, "MAX_COMPRESSED_LOG_BYTES", 10),
            self.assertRaisesRegex(recovery.RecoveryError, "output bound"),
        ):
            recovery.recover_logs(path, self.evidence)
        self.assertEqual(list((self.evidence / "raw").iterdir()), [])
        self.assertFalse((self.evidence / "LOGS.json").exists())

    def test_overlong_log_line_does_not_publish_partial_gzip(self) -> None:
        path = self.archive({recovery.LOG_PREFIX + "query.log": b"x" * 33})
        with (
            self.admitted(path.read_bytes()), mock.patch.object(recovery, "MAX_LINE_BYTES", 32),
            self.assertRaisesRegex(recovery.RecoveryError, "memory bound"),
        ):
            recovery.recover_logs(path, self.evidence)
        self.assertEqual(list((self.evidence / "raw").iterdir()), [])

    def test_expired_recovery_is_rejected_before_log_publication(self) -> None:
        path = self.archive({recovery.LOG_PREFIX + "query.log": b"bounded log\n"})
        with (
            self.admitted(path.read_bytes()),
            mock.patch.object(recovery.time, "monotonic", side_effect=[0, recovery.EXTRACTION_SECONDS + 1]),
            self.assertRaisesRegex(recovery.RecoveryError, "time bound"),
        ):
            recovery.recover_logs(path, self.evidence)
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_corrupt_member_crc_does_not_publish_partial_gzip(self) -> None:
        path = self.root / "diagnostics.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(recovery.LOG_PREFIX + "query.log", b"unique log bytes\n")
        changed = path.read_bytes().replace(b"unique log bytes\n", b"broken log bytes\n", 1)
        path.write_bytes(changed)
        with self.admitted(changed), self.assertRaises(zipfile.BadZipFile):
            recovery.recover_logs(path, self.evidence)
        self.assertEqual(list((self.evidence / "raw").iterdir()), [])

    def test_notes_have_explicit_bounds_while_raw_log_is_complete(self) -> None:
        summary = recovery.LogSummary()
        for _ in range(recovery.MAX_NOTES + 2):
            summary.observe(b"[PROGRESS] " + b"x" * (recovery.MAX_NOTE_CHARS + 1))
        report = summary.report()
        self.assertEqual(len(report["notes"]), recovery.MAX_NOTES)
        self.assertEqual(report["notes_omitted"], 2)
        self.assertTrue(all(row["text_truncated"] for row in report["notes"]))
        self.assertTrue(all(len(row["text"]) == recovery.MAX_NOTE_CHARS for row in report["notes"]))

    def test_failure_receipt_redacts_network_exception_and_never_claims_analysis(self) -> None:
        output = self.root / "recovery"
        with (
            mock.patch.dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_SHA="a" * 40),
            mock.patch.object(recovery, "download", side_effect=OSError("private-bearer https://example.test/?sig=private-url")),
            self.assertRaisesRegex(RuntimeError, "log recovery failed"),
        ):
            recovery.recover(output)
        receipt = (output / "evidence/RECOVERY.json").read_text()
        self.assertNotIn("private-bearer", receipt)
        self.assertNotIn("private-url", receipt)
        record = json.loads(receipt)
        for field in ("diagnostic_recovery_complete", "analysis_executed", "sarif_published", "release_claim_eligible"):
            self.assertIs(record[field], False)
        self.assertEqual(record["failure"]["phase"], "download")

    def test_success_receipt_records_recovery_without_executing_analysis(self) -> None:
        source = self.archive({recovery.LOG_PREFIX + "query.log": b"raw diagnostic\n"}).read_bytes()
        output = self.root / "recovery"
        with (
            self.admitted(source),
            mock.patch.dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_SHA="a" * 40),
            mock.patch.object(recovery, "download", side_effect=lambda path: path.write_bytes(source)),
        ):
            recovery.recover(output)
        record = json.loads((output / "evidence/RECOVERY.json").read_text())
        self.assertIs(record["diagnostic_recovery_complete"], True)
        self.assertEqual(record["log_files"], 1)
        for field in ("analysis_executed", "sarif_published", "release_claim_eligible"):
            self.assertIs(record[field], False)


if __name__ == "__main__":
    unittest.main()
