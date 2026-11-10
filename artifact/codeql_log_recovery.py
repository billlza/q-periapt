"""Recover the retained WASM query logs without executing or publishing analysis."""

from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from evidence_io import EvidenceIOError, consume_regular_snapshot, fresh_output_directory


ARTIFACT_ID = 13609897355
ARCHIVE_BYTES = 600073757
ARCHIVE_SHA256 = "68fc0a7e8f3fc02d9f072acc7eaa457d8e9174ab597d888ca632330ea6ba86c9"
SOURCE_HEAD = "72acaaccde1ca9ea27e5af022da5fbce932ed4e9"
ANALYZED_COMMIT = "cf5bf0195936c2f38197aa571c452a216c757abe"
SOURCE_RUN = 42439010975
LOG_PREFIX = "qperiapt-codeql-database/rust/log/"
TRANSFER_SECONDS = 600
EXTRACTION_SECONDS = 600
MAX_MEMBERS = 512
MAX_LOG_FILES = 64
MAX_LOG_FILE_BYTES = 8 * 1024**3
MAX_TOTAL_LOG_BYTES = 16 * 1024**3
MAX_COMPRESSED_LOG_BYTES = 400 * 1024**2
MAX_LINE_BYTES = 4 * 1024**2
MAX_NOTE_CHARS = 1000
MAX_NOTES = 128


class RecoveryError(ValueError):
    """The fixed diagnostic input or a recovery resource bound was violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryError(message)


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
    temporary.replace(path)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def copy_download(response, output, *, deadline: float) -> None:
    count, digest = 0, hashlib.sha256()
    while block := response.read(1024 * 1024):
        count += len(block)
        require(count <= ARCHIVE_BYTES, "artifact transfer exceeded its exact size")
        require(time.monotonic() <= deadline, "artifact transfer exceeded its time bound")
        digest.update(block)
        output.write(block)
    require(time.monotonic() <= deadline, "artifact transfer exceeded its time bound")
    require(count == ARCHIVE_BYTES and digest.hexdigest() == ARCHIVE_SHA256,
            "artifact size or SHA-256 differs")


def download(path: Path) -> None:
    deadline = time.monotonic() + TRANSFER_SECONDS
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(
        f"https://api.github.com/repos/billlza/q-periapt/actions/artifacts/{ARTIFACT_ID}/zip",
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"]},
    )
    try:
        with opener.open(request, timeout=30):
            raise RecoveryError("artifact API did not return its expected redirect")
    except urllib.error.HTTPError as error:
        with error:
            require(error.code == 302, "artifact API returned an unexpected status")
            url = error.headers.get("Location", "")
    target = urllib.parse.urlsplit(url)
    require(target.scheme == "https" and bool(target.hostname)
            and target.username is None and target.password is None,
            "artifact redirect must be an HTTPS URL without embedded credentials")
    # The authenticated request cannot redirect. The signed URL is opened as a
    # new unauthenticated request and is never included in retained evidence.
    with opener.open(url, timeout=45) as response, path.open("xb") as output:
        copy_download(response, output, deadline=deadline)


def safe_member(info: zipfile.ZipInfo) -> PurePosixPath:
    name = info.filename
    path = PurePosixPath(name)
    require(bool(name) and info.orig_filename == name and "\0" not in name
            and "\\" not in name and not path.is_absolute() and ".." not in path.parts
            and name.rstrip("/") == str(path), "unsafe archive member name")
    file_type = stat.S_IFMT(info.external_attr >> 16)
    require(file_type in ((0, stat.S_IFDIR) if info.is_dir() else (0, stat.S_IFREG)),
            "archive contains a non-regular member")
    require(not info.flag_bits & 1 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
            "archive member encoding is unsupported")
    return path


def select_logs(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    require(len(members) <= MAX_MEMBERS and len(members) == len({m.filename for m in members}),
            "archive member count or uniqueness differs")
    for member in members:
        safe_member(member)
    logs = [m for m in members if not m.is_dir() and m.filename.startswith(LOG_PREFIX)]
    require(0 < len(logs) <= MAX_LOG_FILES, "archive query-log census is invalid")
    require(all(m.file_size <= MAX_LOG_FILE_BYTES for m in logs)
            and sum(m.file_size for m in logs) <= MAX_TOTAL_LOG_BYTES,
            "archive query logs exceed their uncompressed bound")
    return sorted(logs, key=lambda member: member.filename)


@contextmanager
def verified_source(path: Path, *, deadline: float):
    # Hash and copy the same bounded chunks; parse only the private copy.
    # Memory stays at one MiB, while temporary disk is capped by ARCHIVE_BYTES.
    with tempfile.TemporaryFile(mode="w+b", dir=path.parent) as source:
        def capture(chunk: bytes) -> None:
            require(time.monotonic() <= deadline, "query-log recovery exceeded its time bound")
            require(source.write(chunk) == len(chunk), "retained artifact snapshot write was incomplete")

        try:
            snapshot = consume_regular_snapshot(path, maximum=ARCHIVE_BYTES,
                                                label="retained artifact", consume=capture)
        except EvidenceIOError as error:
            raise RecoveryError("retained artifact size or SHA-256 differs: " + str(error)) from error
        require(snapshot.size == ARCHIVE_BYTES and snapshot.sha256 == ARCHIVE_SHA256,
                "retained artifact size or SHA-256 differs")
        require(time.monotonic() <= deadline, "query-log recovery exceeded its time bound")
        source.seek(0)
        yield source


class CompressedBudget:
    def __init__(self) -> None:
        self.bytes = 0

    def write_to(self, output, data: bytes) -> int:
        require(self.bytes + len(data) <= MAX_COMPRESSED_LOG_BYTES,
                "compressed query logs exceed their output bound")
        written = output.write(data)
        require(written == len(data), "compressed query-log write was incomplete")
        self.bytes += written
        return written


class BudgetWriter:
    def __init__(self, output, budget: CompressedBudget) -> None:
        self.output, self.budget = output, budget

    def write(self, data: bytes) -> int:
        return self.budget.write_to(self.output, data)


class LogSummary:
    def __init__(self) -> None:
        self.lines = 0
        self.query_starts = 0
        self.query_completions = 0
        self.cache_eviction_pauses = 0
        self.max_taint_stage_iterations: dict[str, int] = {}
        self.last_line = ""
        self.notes: deque[dict] = deque(maxlen=MAX_NOTES)
        self.note_count = 0

    def observe(self, raw: bytes) -> None:
        self.lines += 1
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        self.last_line = line[:MAX_NOTE_CHARS]
        if "[PROGRESS]" in line:
            self.query_starts += "Starting evaluation of " in line
            self.query_completions += "Evaluation done; writing results to " in line
        self.cache_eviction_pauses += "Pausing evaluation to evict " in line
        if "TaintReach::" in line:
            match = re.search(r"Stage([0-9])::.*\(iteration ([0-9]+)\)", line)
            if match is not None:
                stage, iteration = match.groups()
                self.max_taint_stage_iterations[stage] = max(
                    self.max_taint_stage_iterations.get(stage, 0), int(iteration)
                )
        if ("[PROGRESS]" in line or "This is codeql execute queries " in line
                or "[ERROR]" in line or "[WARN]" in line or "OutOfMemory" in line):
            self.note_count += 1
            self.notes.append({"line": self.lines, "text": line[:MAX_NOTE_CHARS],
                               "text_truncated": len(line) > MAX_NOTE_CHARS})

    def report(self) -> dict:
        return {"lines": self.lines, "query_starts": self.query_starts,
                "query_completions": self.query_completions,
                "cache_eviction_pauses": self.cache_eviction_pauses,
                "max_taint_stage_iterations": self.max_taint_stage_iterations,
                "last_line": self.last_line, "notes": list(self.notes),
                "notes_omitted": max(0, self.note_count - MAX_NOTES)}


def recover_logs(path: Path, evidence: Path) -> list[dict]:
    deadline = time.monotonic() + EXTRACTION_SECONDS
    recovered: list[dict] = []
    budget = CompressedBudget()
    with verified_source(path, deadline=deadline) as source:
        with zipfile.ZipFile(source) as archive:
            logs = select_logs(archive)
            for info in logs:
                require(time.monotonic() <= deadline, "query-log recovery exceeded its time bound")
                relative = safe_member(info).relative_to(PurePosixPath(LOG_PREFIX))
                destination = evidence / "raw" / (str(relative) + ".gz")
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                partial = destination.with_suffix(destination.suffix + ".partial")
                count, digest, summary = 0, hashlib.sha256(), LogSummary()
                partial_created = False
                try:
                    with archive.open(info) as log, partial.open("xb") as output:
                        partial_created = True
                        with gzip.GzipFile(filename="", mode="wb", fileobj=BudgetWriter(output, budget),
                                           compresslevel=6, mtime=0) as compressed:
                            while line := log.readline(MAX_LINE_BYTES + 1):
                                require(len(line) <= MAX_LINE_BYTES, "query-log line exceeds its memory bound")
                                require(time.monotonic() <= deadline, "query-log recovery exceeded its time bound")
                                count += len(line)
                                require(count <= info.file_size, "query-log size exceeds its archive declaration")
                                digest.update(line)
                                compressed.write(line)
                                summary.observe(line)
                    require(count == info.file_size, "query-log size differs from its archive declaration")
                    require(time.monotonic() <= deadline, "query-log recovery exceeded its time bound")
                    partial.replace(destination)
                except BaseException:
                    if partial_created and partial.exists():
                        partial.unlink()
                    raise
                recovered.append({"archive_member": info.filename, "bytes": count,
                                  "sha256": digest.hexdigest(), "gzip": destination.relative_to(evidence).as_posix(),
                                  "gzip_bytes": destination.stat().st_size, "summary": summary.report()})
                write_json(evidence / "LOGS.json", recovered)
    return recovered


def recover(output: Path) -> None:
    root = fresh_output_directory(output, within=Path(os.environ["RUNNER_TEMP"]).resolve(),
                                  label="CodeQL log recovery")
    root.mkdir(mode=0o700, parents=True)
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700)
    report = {"schema": 1, "kind": "qperiapt.codeql_query_log_recovery",
              "diagnostic_recovery_complete": False, "analysis_executed": False,
              "sarif_published": False, "release_claim_eligible": False,
              "artifact_id": ARTIFACT_ID, "artifact_bytes": ARCHIVE_BYTES,
              "artifact_sha256": ARCHIVE_SHA256, "source_run": SOURCE_RUN,
              "source_head": SOURCE_HEAD, "analyzed_commit": ANALYZED_COMMIT,
              "recovery_commit": os.environ.get("GITHUB_SHA"),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    phase = "download"
    write_json(evidence / "RECOVERY.json", report)
    try:
        archive = root / "diagnostics.zip"
        download(archive)
        phase = "recover_logs"
        logs = recover_logs(archive, evidence)
        report.update(diagnostic_recovery_complete=True, log_files=len(logs),
                      log_bytes=sum(row["bytes"] for row in logs),
                      compressed_log_bytes=sum(row["gzip_bytes"] for row in logs))
    except BaseException as error:
        report["failure"] = {"phase": phase, "type": type(error).__name__,
                             "message": str(error) if isinstance(error, RecoveryError)
                             else "operation failed; no credential-bearing exception text retained"}
        raise RuntimeError("CodeQL log recovery failed; inspect evidence/RECOVERY.json") from None
    finally:
        write_json(evidence / "RECOVERY.json", report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    recover(parser.parse_args().output)
