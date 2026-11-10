"""Run a real equal-length ZIP rewrite against one selected source directory."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile


source_root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source_root))
spec = importlib.util.spec_from_file_location("reviewed_log_recovery", source_root / "codeql_log_recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
member = recovery.LOG_PREFIX + "query.log"


def encoded(payload: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(zipfile.ZipInfo(member), payload)
    return output.getvalue()


original, replacement = encoded(b"original\n"), encoded(b"replaced\n")
assert len(original) == len(replacement)
assert hashlib.sha256(original).digest() != hashlib.sha256(replacement).digest()
recovery.ARCHIVE_BYTES = len(original)
recovery.ARCHIVE_SHA256 = hashlib.sha256(original).hexdigest()
report = {
    "source_sha256": hashlib.sha256((source_root / "codeql_log_recovery.py").read_bytes()).hexdigest(),
    "original_archive_sha256": hashlib.sha256(original).hexdigest(),
    "replacement_archive_sha256": hashlib.sha256(replacement).hexdigest(),
    "archive_bytes": len(original),
    "cases": [],
}

for mutate in (False, True):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        path, evidence = root / "diagnostics.zip", root / "evidence"
        path.write_bytes(original)
        evidence.mkdir()
        before = path.stat()
        real_init = zipfile.ZipFile.__init__
        row = {"case": "equal_length_rewrite_restored_mtime" if mutate else "stable"}

        def rewrite_then_open(archive, source, *args, **kwargs):
            if mutate:
                with path.open("r+b") as output:
                    output.write(replacement)
                    output.flush()
                    os.fsync(output.fileno())
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                after = path.stat()
                row.update(same_inode=after.st_ino == before.st_ino,
                           same_size=after.st_size == before.st_size,
                           restored_mtime=after.st_mtime_ns == before.st_mtime_ns,
                           observed_ctime_change=after.st_ctime_ns != before.st_ctime_ns)
            return real_init(archive, source, *args, **kwargs)

        zipfile.ZipFile.__init__ = rewrite_then_open
        try:
            results = recovery.recover_logs(path, evidence)
            row.update(accepted=True, payload=gzip.decompress((evidence / results[0]["gzip"]).read_bytes()).decode(),
                       published_member_sha256=results[0]["sha256"])
        except recovery.RecoveryError as error:
            row.update(accepted=False, error=str(error))
        finally:
            zipfile.ZipFile.__init__ = real_init
        row["retained_files"] = sorted(p.relative_to(evidence).as_posix() for p in evidence.rglob("*") if p.is_file())
        report["cases"].append(row)

print(json.dumps(report, indent=2, sort_keys=True))
