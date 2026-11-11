#!/usr/bin/env python3
"""Prepare the existing Linux CI protobuf version without an APT refresh.

The upstream v21.12 release asset 88187108 reports its size but predates GitHub's
digest field. SHA256 pins the official HTTPS bytes read back on 2026-11-11.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import zipfile

from bounded_process import capture_output


URL = ("https://github.com/protocolbuffers/protobuf/releases/download/"
       "v21.12/protoc-21.12-linux-x86_64.zip")
SIZE = 1_585_982
SHA256 = "3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8"
VERSION = b"libprotoc 3.21.12\n"
SCHEMA = ('syntax = "proto3";\nimport "google/protobuf/timestamp.proto";\n'
          'message Bootstrap { google.protobuf.Timestamp created = 1; }\n')


def command(argv: list[str], *, timeout: int = 10, maximum: int = 4096) -> bytes:
    result = capture_output(argv, timeout_seconds=timeout,
                            maximum_stdout_bytes=maximum, maximum_stderr_bytes=8192)
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} failed ({result.returncode}): "
                           + result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def install(parent: Path) -> dict:
    data = command(["/usr/bin/curl", "-q", "--fail", "--location", "--silent", "--show-error",
                    "--proto", "=https", "--proto-redir", "=https",
                    "--connect-timeout", "15", "--max-time", "90", "--max-filesize", str(SIZE), URL],
                   timeout=100, maximum=SIZE)
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError("protoc archive size or SHA-256 does not match the fixed release")
    directory = Path(tempfile.mkdtemp(prefix="qperiapt-protoc-21.12-", dir=parent)).resolve()
    try:
        # Only authenticated, fixed release bytes reach extraction. The private
        # directory stays outside the checkout and is never reused as a cache.
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.extractall(directory)
        protoc = directory / "bin/protoc"
        protoc.chmod(0o700)
        if command([str(protoc), "--version"]) != VERSION:
            raise RuntimeError("protoc did not report libprotoc 3.21.12")
        schema = directory / "bootstrap.proto"
        schema.write_text(SCHEMA, encoding="utf-8")
        descriptor = directory / "bootstrap.pb"
        command([str(protoc), "--proto_path=" + str(directory),
                 "--proto_path=" + str(directory / "include"),
                 "--descriptor_set_out=" + str(descriptor), str(schema)])
        if not 0 < descriptor.stat().st_size <= 4096:
            raise RuntimeError("protoc did not produce the bootstrap descriptor")
        return {"url": URL, "bytes": len(data), "sha256": SHA256,
                "version": VERSION.decode().strip(), "directory": str(directory),
                "protoc": str(protoc), "include": str(directory / "include"),
                "descriptor_sha256": hashlib.sha256(descriptor.read_bytes()).hexdigest()}
    except BaseException:
        shutil.rmtree(directory)
        raise


def main() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("this fixed protoc asset requires Linux x86_64")
    parent = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    environment = Path(os.environ["GITHUB_ENV"])
    search_path = Path(os.environ["GITHUB_PATH"])
    if "\n" in str(parent) or "\r" in str(parent):
        raise RuntimeError("runner temporary path must fit one environment-file line")
    receipt = install(parent)
    # Publish only after both version and real schema compilation have passed.
    with environment.open("a", encoding="utf-8") as stream:
        stream.write(f"PROTOC={receipt['protoc']}\nPROTOC_INCLUDE={receipt['include']}\n")
    with search_path.open("a", encoding="utf-8") as stream:
        stream.write(str(Path(receipt["protoc"]).parent) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
