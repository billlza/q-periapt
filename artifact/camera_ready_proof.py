#!/usr/bin/env python3
"""Verify and summarize Q-Periapt camera-ready capture bundles.

The verifier proves bundle integrity and internal consistency. It does not turn
producer-originated files into an independent hardware attestation; that would
require an external nonce and a separately trusted signing/TPM identity.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import tomllib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from claim_ledger import (
    EXCLUDED_FROM_TREE,
    LedgerError,
    canonical_file_map_digest,
    canonical_tree_digest,
    repository_paths,
)
from evidence_io import (
    EvidenceIOError,
    parse_strict_json_bytes,
    read_regular_snapshot,
)


MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_LARGE_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_TEXT_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CARGO_SEED_FILE_BYTES = 512 * 1024 * 1024
MAX_CARGO_SEED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_LOGICAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_MEASURED_BINARY_BYTES = 128 * 1024 * 1024
MAX_PROOF_AGE_SECONDS = 7 * 24 * 60 * 60
MANIFEST_SCHEMA_VERSION = 3
CAPTURE_METADATA_SCHEMA_VERSION = 1
RUNNER_PIDS_MAX = 1024
RUNNER_MEMORY_MAX_BYTES = 8 * 1024 * 1024 * 1024
RUNNER_MEMORY_SWAP_MAX_BYTES = 0
RUNNER_FILE_SIZE_MAX_BYTES = 128 * 1024 * 1024
RUNNER_OPEN_FILES_MAX = 4096
HEX_32 = r"[0-9a-f]{32}"
HEX_40 = r"[0-9a-f]{40}"
HEX_64 = r"[0-9a-f]{64}"
MAX_HOST_UNAME_CHARS = 512
HOST_UNAME_PREFIX = "Linux "
HOST_UNAME_SUFFIX = " x86_64"
HOST_UNAME_INNER_MAX = (
    MAX_HOST_UNAME_CHARS - len(HOST_UNAME_PREFIX) - len(HOST_UNAME_SUFFIX)
)
HOST_UNAME_PATTERN = (
    re.escape(HOST_UNAME_PREFIX)
    + rf"[^\r\n]{{1,{HOST_UNAME_INNER_MAX}}}"
    + re.escape(HOST_UNAME_SUFFIX)
)
GROUP_ORDER = ("classical", "standard", "bound", "compat")
GROUPS = set(GROUP_ORDER)
EXPECTED_TOOLS = {
    "ar",
    "as",
    "awk",
    "cargo",
    "cat",
    "cc",
    "chmod",
    "chown",
    "cp",
    "date",
    "dirname",
    "env",
    "find",
    "flock",
    "getent",
    "git",
    "grep",
    "id",
    "ip",
    "ld",
    "mkdir",
    "mktemp",
    "mount",
    "mountpoint",
    "mv",
    "nsenter",
    "passwd",
    "python3",
    "ranlib",
    "readlink",
    "rm",
    "rmdir",
    "rustc",
    "sed",
    "setpriv",
    "sha256sum",
    "sh",
    "sleep",
    "stat",
    "systemd-detect-virt",
    "sysctl",
    "tail",
    "tar",
    "taskset",
    "tc",
    "timeout",
    "umount",
    "unshare",
    "uname",
    "valgrind",
}
BUNDLE_ARTIFACTS = {
    "source_archive": "source.tar",
    "measurements": "measurements.tsv",
    "summary": "summary.json",
    "tool_hashes": "tool-hashes.txt",
    "qdisc_baseline": "netem-baseline.json",
    "qdisc_10ms": "netem-delay-10.json",
    "qdisc_25ms": "netem-delay-25.json",
    "netem_build_log": "netem-build.log",
    "ct_build_log": "ct-build.log",
    "memcheck_control": "memcheck-control.log",
    "memcheck_mlkem_ek": "memcheck-ml-kem-ek.log",
    "memcheck_mlkem_wholedk": "memcheck-ml-kem-wholedk.log",
    "memcheck_mlkem_probe": "memcheck-ml-kem-probe.log",
    "memcheck_leaky_control": "memcheck-leaky-control.log",
    "netem_binary": "netem_bench",
    "mlkem_ct_binary": "ct_decaps_gap",
    "leaky_control_ct_binary": "ct_leaky_control",
    "capture_metadata": "capture-metadata.json",
    "cargo_seed_manifest": "cargo-seed-manifest.tsv",
    "tuning_active": "tuning-active-records.tsv",
    "tuning_after": "tuning-after-records.tsv",
    "qdisc_after": "netem-after.json",
}
BINARY_ARTIFACT_KEYS = {
    "netem_binary",
    "mlkem_ct_binary",
    "leaky_control_ct_binary",
}
TEXT_ARTIFACTS = {
    key
    for key in BUNDLE_ARTIFACTS
    if key not in {"source_archive", *BINARY_ARTIFACT_KEYS}
}
RESERVED_PREFIXES = (
    "host :",
    "cpu  :",
    "pin  :",
    "commit:",
    "source-tree-sha256:",
    "source-archive-sha256:",
    "run-id:",
    "cargo-seed:",
    "bundle-manifest-sha256:",
    "rustc:",
    "rustc ",
    "cargo:",
    "cc:",
    "valgrind:",
    "tool-sha256:",
    "netem-binary-sha256:",
    "mlkem-ct-binary-sha256:",
    "leaky-control-ct-binary-sha256:",
    "== one-way=",
    "rep",
    "netem matrix complete:",
    "  control:",
    "  ml-kem-ek:",
    "  ml-kem-wholedk:",
    "  ml-kem-probe:",
    "  leaky-control:",
    "negative control OK:",
    "DISCRIMINATOR HOLDS:",
    "provenance recheck:",
    "CAMERA_READY_BARE_METAL_PASS",
)


class TranscriptError(ValueError):
    """The capture transcript or bundle is incomplete or inconsistent."""


@dataclass(frozen=True)
class Measurement:
    delay_ms: int
    rep: int
    group: str
    p50: Decimal
    p90: Decimal
    p99: Decimal
    p999: Decimal

    def key(self) -> tuple[int, int, str]:
        return (self.delay_ms, self.rep, self.group)


@dataclass(frozen=True)
class TranscriptEvidence:
    host_uname: str
    cpu: str
    pin: str
    reps: int
    runner_user: str
    runner_uid: int
    runner_gid: int
    rustc_version: str
    cargo_version: str
    cc_version: str
    valgrind_version: str
    cargo_seed_packages: int
    cargo_seed_files: int
    cargo_seed_manifest_sha256: str
    commit: str
    execution_input_sha256: str
    source_archive_sha256: str
    recorded_at: str
    run_id: str
    bundle_manifest_sha256: str
    tools: dict[str, tuple[str, str]]
    measurements: tuple[Measurement, ...]
    binary_hashes: dict[str, str]
    memcheck_errors: dict[str, int]


@dataclass(frozen=True)
class CargoSeedEvidence:
    package_count: int
    file_count: int


def _unique_match(pattern: str, lines: list[str], label: str) -> re.Match[str]:
    matches = [match for line in lines if (match := re.fullmatch(pattern, line))]
    if len(matches) != 1:
        raise TranscriptError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def _strict_json_bytes(data: bytes, label: str) -> Any:
    if len(data) > MAX_MANIFEST_BYTES and label in {"manifest", "summary"}:
        raise TranscriptError(f"{label} exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        return parse_strict_json_bytes(data, label=label)
    except EvidenceIOError as error:
        raise TranscriptError(str(error)) from error


def _read_regular_file(path: pathlib.Path, maximum: int, label: str) -> bytes:
    try:
        return read_regular_snapshot(path, maximum=maximum, label=label).data
    except EvidenceIOError as error:
        raise TranscriptError(str(error)) from error


def _hash_regular_file(path: pathlib.Path, maximum: int, label: str) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TranscriptError(f"{label} is not a regular file")
        if before.st_size > maximum:
            raise TranscriptError(f"{label} exceeds {maximum} bytes")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise TranscriptError(f"{label} exceeds {maximum} bytes")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TranscriptError(f"{label} changed while it was hashed")
        return total, digest.hexdigest()
    finally:
        os.close(descriptor)


def _locked_registry_packages(lock_data: bytes) -> dict[str, str]:
    try:
        document = tomllib.loads(lock_data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise TranscriptError(f"Cargo.lock is invalid: {error}") from error
    if document.get("version") != 4 or not isinstance(document.get("package"), list):
        raise TranscriptError("Cargo.lock must use schema version 4 with a package array")
    packages: dict[str, str] = {}
    registry_source = "registry+https://github.com/rust-lang/crates.io-index"
    for record in document["package"]:
        if not isinstance(record, dict):
            raise TranscriptError("Cargo.lock contains a non-table package record")
        source = record.get("source")
        if source is None:
            continue
        if source != registry_source:
            raise TranscriptError(f"Cargo.lock contains a non-crates.io source: {source!r}")
        name = record.get("name")
        version = record.get("version")
        checksum = record.get("checksum")
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_-]+", name) is None:
            raise TranscriptError("Cargo.lock registry package name is invalid")
        if not isinstance(version, str) or re.fullmatch(r"[A-Za-z0-9.+_-]+", version) is None:
            raise TranscriptError(f"Cargo.lock version is invalid for {name}")
        if not isinstance(checksum, str) or re.fullmatch(HEX_64, checksum) is None:
            raise TranscriptError(f"Cargo.lock checksum is invalid for {name} {version}")
        filename = f"{name}-{version}.crate"
        if filename in packages:
            raise TranscriptError(f"Cargo.lock contains a duplicate registry package: {filename}")
        packages[filename] = checksum
    if not packages:
        raise TranscriptError("Cargo.lock contains no crates.io registry packages")
    return packages


def _parse_cargo_seed_manifest(data: bytes, lock_data: bytes) -> CargoSeedEvidence:
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise TranscriptError("cargo-seed-manifest.tsv is not UTF-8") from error
    if not text.endswith("\n"):
        raise TranscriptError("cargo-seed-manifest.tsv must end with a newline")
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    expected_fields = ["path", "size", "sha256"]
    if reader.fieldnames != expected_fields:
        raise TranscriptError("Cargo seed manifest header is invalid")
    rows: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    total_size = 0
    try:
        for raw in reader:
            if None in raw or any(value is None for value in raw.values()):
                raise TranscriptError("Cargo seed manifest row has an extra or missing field")
            path = raw["path"]
            pure = pathlib.PurePosixPath(path)
            if (
                not path
                or pure.is_absolute()
                or pure.as_posix() != path
                or ".." in pure.parts
                or "\t" in path
                or "\r" in path
                or "\n" in path
            ):
                raise TranscriptError(f"Cargo seed manifest path is unsafe: {path!r}")
            allowed = len(pure.parts) >= 3 and pure.parts[:2] in {
                ("registry", "cache"),
                ("registry", "index"),
            }
            if not allowed:
                raise TranscriptError(f"Cargo seed contains a non-cache/index path: {path}")
            if path in seen:
                raise TranscriptError(f"Cargo seed manifest contains a duplicate path: {path}")
            size_text = raw["size"]
            size = int(size_text)
            if size < 0 or str(size) != size_text:
                raise TranscriptError(f"Cargo seed size is not canonical: {path}")
            digest = raw["sha256"]
            if re.fullmatch(HEX_64, digest) is None:
                raise TranscriptError(f"Cargo seed hash is invalid: {path}")
            seen.add(path)
            rows.append((path, size, digest))
            total_size += size
    except ValueError as error:
        raise TranscriptError("Cargo seed manifest contains an invalid integer") from error
    if not rows or total_size > MAX_CARGO_SEED_BYTES:
        raise TranscriptError("Cargo seed manifest is empty or exceeds the size limit")
    if [path for path, _size, _digest in rows] != sorted(seen):
        raise TranscriptError("Cargo seed manifest paths are not in canonical order")
    canonical = "path\tsize\tsha256\n" + "".join(
        f"{path}\t{size}\t{digest}\n" for path, size, digest in rows
    )
    if canonical.encode("utf-8") != data:
        raise TranscriptError("Cargo seed manifest is not canonical TSV")

    expected_packages = _locked_registry_packages(lock_data)
    crate_rows: dict[str, tuple[str, int, str]] = {}
    for row in rows:
        path = pathlib.PurePosixPath(row[0])
        if path.parts[:2] != ("registry", "cache"):
            continue
        if path.suffix != ".crate":
            raise TranscriptError(f"Cargo registry cache contains a non-crate file: {row[0]}")
        filename = path.name
        if filename in crate_rows:
            raise TranscriptError(f"Cargo seed contains duplicate crate archives: {filename}")
        crate_rows[filename] = row
    if set(crate_rows) != set(expected_packages):
        raise TranscriptError(
            "Cargo seed crate closure differs from Cargo.lock: "
            f"missing={sorted(set(expected_packages) - set(crate_rows))[:5]}, "
            f"extra={sorted(set(crate_rows) - set(expected_packages))[:5]}"
        )
    for filename, checksum in expected_packages.items():
        if crate_rows[filename][2] != checksum:
            raise TranscriptError(f"Cargo seed crate checksum differs from Cargo.lock: {filename}")
    return CargoSeedEvidence(package_count=len(expected_packages), file_count=len(rows))


def _write_cargo_seed_manifest(
    seed_home: pathlib.Path, lockfile: pathlib.Path, output: pathlib.Path
) -> CargoSeedEvidence:
    if seed_home.is_symlink() or not seed_home.is_dir():
        raise TranscriptError("Cargo seed home must be a non-symlink directory")
    rows: list[tuple[str, int, str]] = []
    total_size = 0
    for current, directories, names in os.walk(seed_home, followlinks=False):
        current_path = pathlib.Path(current)
        current_stat = current_path.lstat()
        if (
            not stat.S_ISDIR(current_stat.st_mode)
            or current_stat.st_uid != 0
            or current_stat.st_mode & 0o022
            or current_stat.st_mode & 0o7000
        ):
            raise TranscriptError(f"Cargo seed directory is not root-owned/read-only: {current_path}")
        for directory in directories:
            child = current_path / directory
            child_stat = child.lstat()
            if stat.S_ISLNK(child_stat.st_mode) or not stat.S_ISDIR(child_stat.st_mode):
                raise TranscriptError(f"Cargo seed contains a non-directory child: {child}")
        for name in names:
            path = current_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
                or metadata.st_mode & 0o7111
            ):
                raise TranscriptError(f"Cargo seed file is not a safe root-owned regular file: {path}")
            relative = path.relative_to(seed_home).as_posix()
            size, digest = _hash_regular_file(path, MAX_CARGO_SEED_FILE_BYTES, relative)
            total_size += size
            if total_size > MAX_CARGO_SEED_BYTES:
                raise TranscriptError("Cargo seed exceeds the total size limit")
            rows.append((relative, size, digest))
    rows.sort()
    data = (
        "path\tsize\tsha256\n"
        + "".join(f"{path}\t{size}\t{digest}\n" for path, size, digest in rows)
    ).encode("utf-8")
    lock_data = _read_regular_file(lockfile, MAX_TEXT_ARTIFACT_BYTES, "Cargo.lock")
    evidence = _parse_cargo_seed_manifest(data, lock_data)
    if output.is_symlink():
        raise TranscriptError("Cargo seed manifest output must not be a symlink")
    output.write_bytes(data)
    return evidence


def _decimal(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise TranscriptError(f"{label} is not a decimal") from error
    if not parsed.is_finite() or parsed <= 0:
        raise TranscriptError(f"{label} must be finite and positive")
    return parsed


def _measurement(
    delay_ms: int,
    rep: int,
    group: str,
    p50: str,
    p90: str,
    p99: str,
    p999: str,
) -> Measurement:
    values = tuple(
        _decimal(value, f"delay={delay_ms}/rep={rep}/{group}/{label}")
        for value, label in ((p50, "p50"), (p90, "p90"), (p99, "p99"), (p999, "p99.9"))
    )
    if values != tuple(sorted(values)):
        raise TranscriptError(
            f"percentiles are not monotonic for delay={delay_ms}, rep={rep}, group={group}"
        )
    return Measurement(delay_ms, rep, group, *values)


def _expected_measurement_keys() -> list[tuple[int, int, str]]:
    return [
        (delay, rep, group)
        for delay, count in ((0, 20), (10, 6), (25, 4))
        for rep in range(1, count + 1)
        for group in GROUP_ORDER
    ]


def _parse_tools(lines: list[str], pattern: re.Pattern[str]) -> dict[str, tuple[str, str]]:
    tools: dict[str, tuple[str, str]] = {}
    for line in lines:
        match = pattern.fullmatch(line)
        if not match:
            continue
        name = match.group("name")
        if name in tools:
            raise TranscriptError(f"duplicate tool identity: {name}")
        tools[name] = (match.group("hash"), match.group("path"))
    if set(tools) != EXPECTED_TOOLS:
        raise TranscriptError(
            f"tool identity set mismatch: got={sorted(tools)}, expected={sorted(EXPECTED_TOOLS)}"
        )
    return tools


def _parse_transcript(text: str) -> TranscriptEvidence:
    lines = [line.rstrip("\r") for line in text.splitlines()]
    nonempty = [line for line in lines if line]
    if not nonempty:
        raise TranscriptError("transcript is empty")
    if any("error:" in line.lower() for line in lines):
        raise TranscriptError("transcript contains an error line")

    host_pattern = re.compile(
        rf"host : (?P<uname>{HOST_UNAME_PATTERN})    date: "
        r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}Z)"
    )
    host = _unique_match(host_pattern.pattern, lines, "native Linux host line")
    host_uname = host.group("uname")
    recorded_at = host.group("date")
    try:
        dt.datetime.strptime(recorded_at, "%Y-%m-%dT%H:%MZ")
    except ValueError as error:
        raise TranscriptError("host timestamp is invalid") from error
    pin_pattern = re.compile(
        r"pin  : cores (?P<pin>[0-9,-]+)   reps: (?P<reps>[0-9]+)   "
        r"supervisor: root   runner-user: (?P<runner_user>[A-Za-z0-9._-]+)   "
        r"runner-uid: (?P<runner_uid>[1-9][0-9]*)   runner-gid: "
        r"(?P<runner_gid>[1-9][0-9]*)   no-new-privs: yes   cgroup-v2: yes"
    )
    pin = _unique_match(pin_pattern.pattern, lines, "runner isolation line")
    reps = int(pin.group("reps"))
    if reps != 20:
        raise TranscriptError(f"top-level repetition count must be 20, got {reps}")
    cpu_pattern = re.compile(r"cpu  : (?P<cpu>.+)")
    rustc_header_pattern = re.compile(r"rustc:")
    rustc_pattern = re.compile(r"rustc [0-9].+")
    cargo_pattern = re.compile(r"cargo: cargo [0-9].+")
    cc_pattern = re.compile(r"cc: .+")
    valgrind_pattern = re.compile(r"valgrind: valgrind-.+")
    cpu = _unique_match(cpu_pattern.pattern, lines, "CPU line").group("cpu")
    _unique_match(rustc_header_pattern.pattern, lines, "rustc header")
    _unique_match(rustc_pattern.pattern, lines, "rustc version line")
    cargo = _unique_match(cargo_pattern.pattern, lines, "cargo version line").group(0)[7:]
    cc = _unique_match(cc_pattern.pattern, lines, "C compiler version line").group(0)[4:]
    valgrind = _unique_match(
        valgrind_pattern.pattern, lines, "Valgrind version line"
    ).group(0)[10:]
    rustc_header_index = lines.index("rustc:")
    cargo_line_index = lines.index(f"cargo: {cargo}")
    if cargo_line_index <= rustc_header_index + 1:
        raise TranscriptError("rustc version block is empty or out of order")
    rustc_version = "\n".join(lines[rustc_header_index + 1 : cargo_line_index])
    if not re.fullmatch(r"rustc [0-9].+(?:\n.+)*", rustc_version):
        raise TranscriptError("rustc version block is malformed")

    cargo_seed_pattern = re.compile(
        rf"cargo-seed: packages=(?P<packages>[1-9][0-9]*) "
        rf"files=(?P<files>[1-9][0-9]*) manifest-sha256=(?P<hash>{HEX_64})"
    )
    cargo_seed = _unique_match(cargo_seed_pattern.pattern, lines, "Cargo seed line")

    commit_pattern = re.compile(rf"commit: (?P<value>{HEX_40})")
    source_pattern = re.compile(
        rf"source-tree-sha256: (?P<value>{HEX_64})   dirty: false"
    )
    archive_pattern = re.compile(rf"source-archive-sha256: (?P<value>{HEX_64})")
    run_id_pattern = re.compile(rf"run-id: (?P<value>{HEX_32})")
    bundle_pattern = re.compile(rf"bundle-manifest-sha256: (?P<value>{HEX_64})")
    commit = _unique_match(commit_pattern.pattern, lines, "commit line").group("value")
    source = _unique_match(source_pattern.pattern, lines, "clean source digest line").group(
        "value"
    )
    archive = _unique_match(archive_pattern.pattern, lines, "source archive hash").group(
        "value"
    )
    run_id = _unique_match(run_id_pattern.pattern, lines, "run id").group("value")
    bundle_hash = _unique_match(bundle_pattern.pattern, lines, "bundle manifest hash").group(
        "value"
    )

    binary_patterns = {
        "netem": re.compile(rf"netem-binary-sha256: (?P<value>{HEX_64})"),
        "mlkem": re.compile(rf"mlkem-ct-binary-sha256: (?P<value>{HEX_64})"),
        "leaky_control": re.compile(
            rf"leaky-control-ct-binary-sha256: (?P<value>{HEX_64})"
        ),
    }
    binary_hashes = {
        name: _unique_match(pattern.pattern, lines, f"{name} binary hash").group("value")
        for name, pattern in binary_patterns.items()
    }
    tool_pattern = re.compile(
        rf"tool-sha256: (?P<name>[a-z0-9-]+) (?P<hash>{HEX_64}) (?P<path>/\S+)"
    )
    tools = _parse_tools(lines, tool_pattern)

    header_pattern = re.compile(
        r"== one-way=(?P<delay>0|10|25) ms \(RTT=(?P<rtt>0|20|50) ms\), "
        r"reps=(?P<reps>[0-9]+) =="
    )
    row_pattern = re.compile(
        r"rep(?P<rep>[0-9]+)\s+(?P<group>classical|standard|bound|compat)\s+"
        r"p50 = (?P<p50>[0-9]+\.[0-9])  p90 = (?P<p90>[0-9]+\.[0-9])  "
        r"p99 = (?P<p99>[0-9]+\.[0-9])  p99\.9 = (?P<p999>[0-9]+\.[0-9])"
    )
    expected_reps = {0: 20, 10: 6, 25: 4}
    expected_rtt = {0: 0, 10: 20, 25: 50}
    observed_headers: list[int] = []
    measurements: list[Measurement] = []
    current_delay: int | None = None
    for line in lines:
        if header := header_pattern.fullmatch(line):
            delay = int(header.group("delay"))
            if delay in observed_headers:
                raise TranscriptError(f"duplicate netem section for delay {delay}")
            if int(header.group("rtt")) != expected_rtt[delay]:
                raise TranscriptError(f"RTT mismatch for delay {delay}")
            if int(header.group("reps")) != expected_reps[delay]:
                raise TranscriptError(f"repetition mismatch for delay {delay}")
            observed_headers.append(delay)
            current_delay = delay
            continue
        if row := row_pattern.fullmatch(line):
            if current_delay is None:
                raise TranscriptError("measurement row precedes a netem section")
            measurements.append(
                _measurement(
                    current_delay,
                    int(row.group("rep")),
                    row.group("group"),
                    row.group("p50"),
                    row.group("p90"),
                    row.group("p99"),
                    row.group("p999"),
                )
            )
    if observed_headers != [0, 10, 25]:
        raise TranscriptError(f"netem section order mismatch: {observed_headers}")
    expected_keys = _expected_measurement_keys()
    actual_keys = [row.key() for row in measurements]
    if actual_keys != expected_keys:
        raise TranscriptError("netem row order/set does not match the registered matrix")
    expected_runs = len(expected_keys)
    matrix_pattern = re.compile(
        r"netem matrix complete: (?P<got>[0-9]+)/(?P<expected>[0-9]+) group-runs"
    )
    matrix = _unique_match(matrix_pattern.pattern, lines, "netem completion line")
    if int(matrix.group("got")) != expected_runs or int(matrix.group("expected")) != expected_runs:
        raise TranscriptError("netem completion count does not match the row set")

    memcheck_pattern = re.compile(
        r"  (?P<label>control|ml-kem-ek|ml-kem-wholedk|ml-kem-probe|leaky-control):\s+"
        r"ERROR SUMMARY: (?P<count>[0-9]+) errors(?: .*)?"
    )
    memcheck_errors: dict[str, int] = {}
    for line in lines:
        match = memcheck_pattern.fullmatch(line)
        if not match:
            continue
        label = match.group("label")
        if label in memcheck_errors:
            raise TranscriptError(f"duplicate Memcheck summary: {label}")
        memcheck_errors[label] = int(match.group("count"))
    expected_memcheck = {
        "control",
        "ml-kem-ek",
        "ml-kem-wholedk",
        "ml-kem-probe",
        "leaky-control",
    }
    if set(memcheck_errors) != expected_memcheck:
        raise TranscriptError("Memcheck summary set is incomplete")
    if memcheck_errors["control"] <= 0:
        raise TranscriptError("CT negative control is not positive")
    for label in ("ml-kem-ek", "ml-kem-wholedk"):
        if memcheck_errors[label] <= 0:
            raise TranscriptError(f"{label} positive control reported no Memcheck errors")
    if memcheck_errors["ml-kem-ek"] != memcheck_errors["ml-kem-wholedk"]:
        raise TranscriptError("ML-KEM ek and whole-dk positive controls disagree")
    if memcheck_errors["ml-kem-probe"] != 0:
        raise TranscriptError("ml-kem-probe reported Memcheck errors")
    if memcheck_errors["leaky-control"] <= 0:
        raise TranscriptError("synthetic planted-leak discriminator is not positive")
    control_pattern = re.compile(r"negative control OK: (?P<errors>[1-9][0-9]*) errors")
    control = _unique_match(control_pattern.pattern, lines, "CT negative control")
    if int(control.group("errors")) != memcheck_errors["control"]:
        raise TranscriptError("negative-control count does not match its raw summary")
    discriminator_pattern = re.compile(
        r"DISCRIMINATOR HOLDS: ML-KEM probe=0 vs planted secret branch="
        r"(?P<errors>[1-9][0-9]*)"
    )
    discriminator = _unique_match(
        discriminator_pattern.pattern, lines, "CT discriminator"
    )
    if int(discriminator.group("errors")) != memcheck_errors["leaky-control"]:
        raise TranscriptError(
            "synthetic planted-leak discriminator count does not match its raw summary"
        )
    provenance_pattern = re.compile(
        r"provenance recheck: commit/source/archive/tools/binaries/cargo-seed unchanged"
    )
    _unique_match(provenance_pattern.pattern, lines, "provenance recheck")

    marker_pattern = re.compile(
        rf"CAMERA_READY_BARE_METAL_PASS netem_runs=(?P<runs>[0-9]+) ct_mode=native "
        rf"commit=(?P<commit>{HEX_40}) source_sha256=(?P<source>{HEX_64}) "
        rf"archive_sha256=(?P<archive>{HEX_64}) netem_sha256=(?P<netem>{HEX_64}) "
        rf"mlkem_ct_sha256=(?P<mlkem>{HEX_64}) "
        rf"leaky_control_ct_sha256=(?P<leaky_control>{HEX_64}) "
        rf"run_id=(?P<run_id>{HEX_32}) bundle_manifest_sha256=(?P<bundle>{HEX_64})"
    )
    marker = _unique_match(marker_pattern.pattern, lines, "camera-ready success marker")
    if nonempty[-1] != marker.group(0):
        raise TranscriptError("success marker must be the final non-empty line after cleanup")
    expected_marker = {
        "runs": str(expected_runs),
        "commit": commit,
        "source": source,
        "archive": archive,
        "netem": binary_hashes["netem"],
        "mlkem": binary_hashes["mlkem"],
        "leaky_control": binary_hashes["leaky_control"],
        "run_id": run_id,
        "bundle": bundle_hash,
    }
    for field, expected in expected_marker.items():
        if marker.group(field) != expected:
            raise TranscriptError(f"success marker {field} does not match the transcript")

    allowed_reserved_patterns = (
        host_pattern,
        pin_pattern,
        cpu_pattern,
        rustc_header_pattern,
        rustc_pattern,
        cargo_pattern,
        cc_pattern,
        valgrind_pattern,
        cargo_seed_pattern,
        commit_pattern,
        source_pattern,
        archive_pattern,
        run_id_pattern,
        bundle_pattern,
        *binary_patterns.values(),
        tool_pattern,
        header_pattern,
        row_pattern,
        matrix_pattern,
        memcheck_pattern,
        control_pattern,
        discriminator_pattern,
        provenance_pattern,
        marker_pattern,
    )
    for line in lines:
        if line.startswith(RESERVED_PREFIXES) and not any(
            pattern.fullmatch(line) for pattern in allowed_reserved_patterns
        ):
            raise TranscriptError(f"malformed reserved-prefix line: {line[:120]}")

    return TranscriptEvidence(
        host_uname=host_uname,
        cpu=cpu,
        pin=pin.group("pin"),
        reps=reps,
        runner_user=pin.group("runner_user"),
        runner_uid=int(pin.group("runner_uid")),
        runner_gid=int(pin.group("runner_gid")),
        rustc_version=rustc_version,
        cargo_version=cargo,
        cc_version=cc,
        valgrind_version=valgrind,
        cargo_seed_packages=int(cargo_seed.group("packages")),
        cargo_seed_files=int(cargo_seed.group("files")),
        cargo_seed_manifest_sha256=cargo_seed.group("hash"),
        commit=commit,
        execution_input_sha256=source,
        source_archive_sha256=archive,
        recorded_at=recorded_at,
        run_id=run_id,
        bundle_manifest_sha256=bundle_hash,
        tools=tools,
        measurements=tuple(measurements),
        binary_hashes=binary_hashes,
        memcheck_errors=memcheck_errors,
    )


def _parse_measurements_tsv(data: bytes) -> tuple[Measurement, ...]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise TranscriptError("measurements.tsv is not UTF-8") from error
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    expected_fields = ["delay_ms", "rep", "group", "p50_us", "p90_us", "p99_us", "p999_us"]
    if reader.fieldnames != expected_fields:
        raise TranscriptError(f"measurement TSV header mismatch: {reader.fieldnames}")
    rows: list[Measurement] = []
    try:
        for raw in reader:
            if None in raw or any(value is None for value in raw.values()):
                raise TranscriptError("measurement TSV row has an extra or missing field")
            group = raw["group"]
            if group not in GROUPS:
                raise TranscriptError(f"unknown measurement group: {group}")
            rows.append(
                _measurement(
                    int(raw["delay_ms"]),
                    int(raw["rep"]),
                    group,
                    raw["p50_us"],
                    raw["p90_us"],
                    raw["p99_us"],
                    raw["p999_us"],
                )
            )
    except ValueError as error:
        raise TranscriptError(f"measurement TSV has an invalid integer: {error}") from error
    if [row.key() for row in rows] != _expected_measurement_keys():
        raise TranscriptError("measurement TSV row order/set does not match the registered matrix")
    return tuple(rows)


def _median(values: list[Decimal]) -> Decimal:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / Decimal(2)


def measurement_summary(rows: tuple[Measurement, ...]) -> dict[str, Any]:
    delays: dict[str, Any] = {}
    for delay in (0, 10, 25):
        groups: dict[str, Any] = {}
        for group in GROUP_ORDER:
            selected = [row for row in rows if row.delay_ms == delay and row.group == group]
            groups[group] = {
                field: format(_median([getattr(row, attr) for row in selected]), "f")
                for field, attr in (
                    ("p50_us", "p50"),
                    ("p90_us", "p90"),
                    ("p99_us", "p99"),
                    ("p999_us", "p999"),
                )
            }
        delays[str(delay)] = groups
    return {
        "schema_version": 1,
        "unit": "microseconds",
        "estimator": "median_of_per_run_percentiles",
        "delays_ms": delays,
    }


def _canonical_summary_bytes(rows: tuple[Measurement, ...]) -> bytes:
    return (
        json.dumps(measurement_summary(rows), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def validate_netem_document(value: Any, expected_delay_ms: int) -> None:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise TranscriptError("qdisc snapshot must contain exactly one object")
    qdisc = value[0]
    allowed_qdisc_fields = {"kind", "handle", "root", "parent", "refcnt", "options"}
    extra_qdisc_fields = set(qdisc) - allowed_qdisc_fields
    if extra_qdisc_fields:
        raise TranscriptError(
            f"qdisc snapshot has unknown fields: {sorted(extra_qdisc_fields)}"
        )
    if qdisc.get("root") is not True or qdisc.get("parent") not in (None, "root"):
        raise TranscriptError("qdisc must be attached at the root")
    refcnt = qdisc.get("refcnt")
    if refcnt is not None and (type(refcnt) is not int or refcnt <= 0):
        raise TranscriptError("qdisc refcnt must be a positive integer when present")
    if expected_delay_ms == 0:
        if qdisc.get("kind") != "noqueue":
            raise TranscriptError("baseline qdisc must be exactly one noqueue qdisc")
        if qdisc.get("handle") not in (None, "0:"):
            raise TranscriptError("baseline noqueue qdisc has an unexpected handle")
        options = qdisc.get("options")
        if options not in (None, {}, []):
            raise TranscriptError("baseline noqueue qdisc must not have shaping options")
        return
    if qdisc.get("kind") != "netem" or qdisc.get("handle") != "51ab:":
        raise TranscriptError("netem qdisc kind or owned handle is wrong")
    options = qdisc.get("options")
    if not isinstance(options, dict):
        raise TranscriptError("netem qdisc lacks structured options")
    allowed = {
        "limit",
        "delay",
        "jitter",
        "loss",
        "duplicate",
        "reorder",
        "corrupt",
        "rate",
        "gap",
        "correlation",
        "ecn",
    }
    extra = set(options) - allowed
    if extra:
        raise TranscriptError(f"netem qdisc has unknown options: {sorted(extra)}")
    if options.get("delay") != expected_delay_ms * 1000:
        raise TranscriptError(
            f"netem delay is not exactly {expected_delay_ms} ms: {options.get('delay')!r}"
        )
    if options.get("limit", 1000) != 1000:
        raise TranscriptError("netem packet limit differs from the default 1000")
    for key in ("jitter", "loss", "duplicate", "reorder", "corrupt", "rate", "gap", "correlation"):
        if options.get(key, 0) not in (0, 0.0, None, False, "0", "0.0"):
            raise TranscriptError(f"netem contains forbidden non-zero {key}")
    if options.get("ecn", False) not in (False, 0, None):
        raise TranscriptError("netem ECN option must be disabled")


def validate_netem_bytes(data: bytes, expected_delay_ms: int) -> None:
    validate_netem_document(_strict_json_bytes(data, "qdisc snapshot"), expected_delay_ms)


def _parse_tuning_records(
    active_data: bytes, after_data: bytes
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    def rows(data: bytes, expected_fields: list[str], label: str) -> list[dict[str, str]]:
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise TranscriptError(f"{label} is not UTF-8") from error
        if not text.endswith("\n"):
            raise TranscriptError(f"{label} must end with a newline")
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
        if reader.fieldnames != expected_fields:
            raise TranscriptError(f"{label} header is invalid")
        parsed: list[dict[str, str]] = []
        for raw in reader:
            if None in raw or any(value is None for value in raw.values()):
                raise TranscriptError(f"{label} row has an extra or missing field")
            if any("\t" in value or "\r" in value or "\n" in value for value in raw.values()):
                raise TranscriptError(f"{label} row contains an unsafe field")
            parsed.append(dict(raw))
        if not parsed:
            raise TranscriptError(f"{label} is empty")
        return parsed

    active = rows(
        active_data,
        ["kind", "name", "before", "active"],
        "tuning-active-records.tsv",
    )
    after = rows(
        after_data,
        ["kind", "name", "before", "active", "after"],
        "tuning-after-records.tsv",
    )
    if len(active) != len(after):
        raise TranscriptError("active/after tuning record counts differ")
    for active_row, after_row in zip(active, after, strict=True):
        if active_row != {key: after_row[key] for key in active_row}:
            raise TranscriptError("active/after tuning records differ")
        if after_row["after"] != active_row["before"]:
            raise TranscriptError(f"host tuning was not restored: {active_row['name']}")

    expected_sysctls = [
        ("net.ipv4.tcp_tw_reuse", "1", r"[0-9]+"),
        ("net.ipv4.ip_local_port_range", "1024 65535", r"[0-9]+ [0-9]+"),
        ("net.ipv4.tcp_fin_timeout", "3", r"[0-9]+"),
    ]
    sysctls = [row for row in active if row["kind"] == "sysctl"]
    if [(row["name"], row["active"]) for row in sysctls] != [
        (name, wanted) for name, wanted, _pattern in expected_sysctls
    ]:
        raise TranscriptError("sysctl tuning set/order is invalid")
    for row, (_name, _wanted, before_pattern) in zip(sysctls, expected_sysctls, strict=True):
        if re.fullmatch(before_pattern, row["before"]) is None:
            raise TranscriptError(f"sysctl before value is invalid: {row['name']}")

    sysfs = [row for row in active if row["kind"] == "sysfs"]
    if len(sysctls) + len(sysfs) != len(active):
        raise TranscriptError("tuning records contain an unknown kind")
    governors = [
        row
        for row in sysfs
        if re.fullmatch(
            r"/sys/devices/system/cpu/cpufreq/policy[0-9]+/scaling_governor",
            row["name"],
        )
    ]
    controls = [row for row in sysfs if row not in governors]
    if not governors or [row["name"] for row in governors] != sorted(
        row["name"] for row in governors
    ):
        raise TranscriptError("CPU governor records are missing or not canonical")
    for row in governors:
        if row["active"] != "performance" or re.fullmatch(
            r"[A-Za-z0-9_-]+", row["before"]
        ) is None:
            raise TranscriptError(f"CPU governor record is invalid: {row['name']}")
    if len(controls) != 1:
        raise TranscriptError("exactly one boost/turbo control is required")
    control = controls[0]
    expected_control = {
        "/sys/devices/system/cpu/cpufreq/boost": "0",
        "/sys/devices/system/cpu/intel_pstate/no_turbo": "1",
    }
    if (
        control["name"] not in expected_control
        or control["active"] != expected_control[control["name"]]
        or re.fullmatch(r"[01]", control["before"]) is None
    ):
        raise TranscriptError("boost/turbo record is invalid")
    if active != [*sysctls, *governors, control]:
        raise TranscriptError("tuning record order is invalid")
    return sysctls, sysfs


def _capture_metadata_bytes(
    *,
    host_uname: str,
    cpu: str,
    recorded_at: str,
    pin: str,
    reps: int,
    runner_user: str,
    runner_uid: int,
    runner_gid: int,
    rustc_version: str,
    cargo_version: str,
    cc_version: str,
    valgrind_version: str,
    tuning_active_data: bytes,
    tuning_after_data: bytes,
    qdisc_baseline_data: bytes,
    qdisc_after_data: bytes,
    cargo_seed_manifest_data: bytes,
    lock_data: bytes,
) -> bytes:
    if re.fullmatch(HOST_UNAME_PATTERN, host_uname) is None:
        raise TranscriptError("capture host uname is invalid")
    if not cpu or "\n" in cpu or "\r" in cpu:
        raise TranscriptError("capture CPU name is invalid")
    try:
        dt.datetime.strptime(recorded_at, "%Y-%m-%dT%H:%MZ")
    except ValueError as error:
        raise TranscriptError("capture timestamp is invalid") from error
    if re.fullmatch(r"[0-9,-]+", pin) is None or reps != 20:
        raise TranscriptError("capture affinity/repetition contract is invalid")
    if re.fullmatch(r"[A-Za-z0-9._-]+", runner_user) is None:
        raise TranscriptError("capture runner user is invalid")
    if type(runner_uid) is not int or runner_uid <= 0 or type(runner_gid) is not int or runner_gid <= 0:
        raise TranscriptError("capture runner identity is invalid")
    if re.fullmatch(r"rustc [0-9].+(?:\n.+)*", rustc_version) is None:
        raise TranscriptError("capture rustc version is invalid")
    if re.fullmatch(r"cargo [0-9].+", cargo_version) is None:
        raise TranscriptError("capture cargo version is invalid")
    if not cc_version or "\n" in cc_version or "\r" in cc_version:
        raise TranscriptError("capture C compiler version is invalid")
    if re.fullmatch(r"valgrind-.+", valgrind_version) is None:
        raise TranscriptError("capture Valgrind version is invalid")

    sysctls, sysfs = _parse_tuning_records(tuning_active_data, tuning_after_data)
    baseline = _strict_json_bytes(qdisc_baseline_data, "baseline qdisc")
    after = _strict_json_bytes(qdisc_after_data, "restored qdisc")
    validate_netem_document(baseline, 0)
    validate_netem_document(after, 0)
    if qdisc_after_data != qdisc_baseline_data:
        raise TranscriptError("restored qdisc bytes differ from the frozen baseline")
    seed = _parse_cargo_seed_manifest(cargo_seed_manifest_data, lock_data)
    document = {
        "schema_version": CAPTURE_METADATA_SCHEMA_VERSION,
        "kind": "qperiapt-camera-ready-capture-metadata",
        "host": {
            "uname": host_uname,
            "cpu": cpu,
            "recorded_at": recorded_at,
            "pin": pin,
            "reps": reps,
        },
        "runner": {
            "user": runner_user,
            "uid": runner_uid,
            "gid": runner_gid,
            "clear_groups": True,
            "no_new_privs": True,
            "cgroup_v2": True,
            "measurement_network_namespace": "loopback_only",
            "private_mount_namespace": True,
            "private_ipc_namespace": True,
            "private_tmpfs": True,
            "recursive_read_only_host_mounts": True,
            "pids_max": RUNNER_PIDS_MAX,
            "memory_max_bytes": RUNNER_MEMORY_MAX_BYTES,
            "memory_swap_max_bytes": RUNNER_MEMORY_SWAP_MAX_BYTES,
            "file_size_max_bytes": RUNNER_FILE_SIZE_MAX_BYTES,
            "open_files_max": RUNNER_OPEN_FILES_MAX,
            "workspace_bytes_max": RUNNER_MEMORY_MAX_BYTES,
            "workspace_inodes_max": 524288,
        },
        "toolchain": {
            "rustc": rustc_version,
            "cargo": cargo_version,
            "cc": cc_version,
            "valgrind": valgrind_version,
        },
        "cargo_seed": {
            "manifest_sha256": hashlib.sha256(cargo_seed_manifest_data).hexdigest(),
            "package_count": seed.package_count,
            "file_count": seed.file_count,
            "fresh_home_per_build": ["netem", "ct"],
            "build_network_namespace": "none",
        },
        "tuning": {
            "sysctl": sysctls,
            "sysfs": sysfs,
            "qdisc_baseline": baseline,
            "qdisc_after": after,
            "restored": True,
        },
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _write_capture_metadata(output: pathlib.Path, **kwargs: Any) -> None:
    data = _capture_metadata_bytes(**kwargs)
    if output.is_symlink():
        raise TranscriptError("capture metadata output must not be a symlink")
    output.write_bytes(data)


def _freeze_binary(source: pathlib.Path, output: pathlib.Path, expected_uid: int) -> str:
    if type(expected_uid) is not int or expected_uid <= 0:
        raise TranscriptError("expected measured-binary owner uid is invalid")
    source_flags = (
        os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, source_flags)
    output_fd: int | None = None
    output_created = False
    try:
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_MEASURED_BINARY_BYTES
            or before.st_mode & 0o111 == 0
        ):
            raise TranscriptError("measured binary source metadata is unsafe")
        output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            output_flags |= os.O_NOFOLLOW
        output_fd = os.open(output, output_flags, 0o600)
        output_created = True
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(source_fd, 1024 * 1024):
            total += len(chunk)
            if total > MAX_MEASURED_BINARY_BYTES:
                raise TranscriptError("measured binary grew beyond the size limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                if written <= 0:
                    raise TranscriptError("measured binary copy was incomplete")
                view = view[written:]
        if total != before.st_size:
            raise TranscriptError("measured binary size changed during copy")
        after = os.fstat(source_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise TranscriptError("measured binary changed during copy")
        os.fsync(output_fd)
        return digest.hexdigest()
    except BaseException:
        if output_created:
            try:
                output.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(source_fd)
        if output_fd is not None:
            os.close(output_fd)


def _archive_files(data: bytes) -> dict[str, tuple[bytes, int]]:
    files: dict[str, tuple[bytes, int]] = {}
    member_count = 0
    logical_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise TranscriptError("source archive contains too many members")
                name = member.name.removeprefix("./")
                path = pathlib.PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or not path.parts:
                    raise TranscriptError(f"source archive contains unsafe path: {member.name}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise TranscriptError(f"source archive contains non-regular member: {name}")
                sparse_headers = {
                    key
                    for key in member.pax_headers
                    if "sparse" in key.lower() or key == "SCHILY.realsize"
                }
                if (
                    member.type == tarfile.GNUTYPE_SPARSE
                    or getattr(member, "sparse", None)
                    or sparse_headers
                ):
                    raise TranscriptError(f"source archive contains a sparse member: {name}")
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise TranscriptError(f"source archive member is too large: {name}")
                logical_size += member.size
                if logical_size > MAX_ARCHIVE_LOGICAL_BYTES:
                    raise TranscriptError("source archive logical contents exceed the size limit")
                if name in files:
                    raise TranscriptError(f"source archive contains duplicate member: {name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise TranscriptError(f"cannot read source archive member: {name}")
                mode = member.mode & 0o777
                if mode not in {0o644, 0o664, 0o755, 0o775}:
                    raise TranscriptError(f"source archive member has unsafe mode: {name}")
                normalized_mode = 0o755 if mode & 0o111 else 0o644
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise TranscriptError(f"source archive member size is inconsistent: {name}")
                files[name] = (content, normalized_mode)
    except (tarfile.TarError, OSError) as error:
        raise TranscriptError(f"source archive is invalid: {error}") from error
    if not files:
        raise TranscriptError("source archive contains no files")
    return files


def _git_tree(root: pathlib.Path, commit: str) -> dict[str, tuple[bytes, int]]:
    output = _git("ls-tree", "-rz", "--full-tree", commit, root=root).stdout
    tree: dict[str, tuple[bytes, int]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise TranscriptError("referenced Git tree has a malformed entry") from error
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise TranscriptError(f"referenced Git tree has unsupported entry: {path}")
        if path in tree:
            raise TranscriptError(f"referenced Git tree has duplicate path: {path}")
        content = _git("cat-file", "blob", object_id.decode("ascii"), root=root).stdout
        tree[path] = (content, 0o755 if mode == b"100755" else 0o644)
    if not tree:
        raise TranscriptError("referenced Git tree contains no regular files")
    return tree


def _git(*args: str, root: pathlib.Path, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    process = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={root}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            *args,
        ],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    if check and process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise TranscriptError(f"git {' '.join(args)} failed: {detail}")
    return process


def _verify_source_provenance(
    root: pathlib.Path, archive_data: bytes, evidence: TranscriptEvidence
) -> None:
    _git("cat-file", "-e", f"{evidence.commit}^{{commit}}", root=root)
    ancestor = _git("merge-base", "--is-ancestor", evidence.commit, "HEAD", root=root, check=False)
    if ancestor.returncode == 1:
        raise TranscriptError("capture commit is not an ancestor of current HEAD")
    if ancestor.returncode != 0:
        raise TranscriptError("cannot verify capture-commit ancestry")
    bundle_hash = hashlib.sha256(archive_data).hexdigest()
    if bundle_hash != evidence.source_archive_sha256:
        raise TranscriptError("source archive hash does not match transcript")
    archive_files = _archive_files(archive_data)
    if archive_files != _git_tree(root, evidence.commit):
        raise TranscriptError("source archive members do not match the referenced Git tree")
    archive_digest = canonical_file_map_digest(
        {path: content for path, (content, _mode) in archive_files.items()}
    )
    if archive_digest != evidence.execution_input_sha256:
        raise TranscriptError("source archive execution-input digest does not match transcript")
    current_digest = canonical_tree_digest(root, repository_paths(root))
    if current_digest != evidence.execution_input_sha256:
        raise TranscriptError("current execution inputs differ from the capture commit")
    changed = _git("diff", "--name-only", "-z", evidence.commit, "HEAD", root=root).stdout
    changed_paths = {part.decode("utf-8") for part in changed.split(b"\0") if part}
    unexpected = changed_paths - EXCLUDED_FROM_TREE
    if unexpected:
        raise TranscriptError(
            f"successor commit changes execution inputs: {sorted(unexpected)[:5]}"
        )
    working_paths: set[str] = set()
    for args in (
        ("diff", "--name-only", "-z", "HEAD"),
        ("diff", "--cached", "--name-only", "-z", "HEAD"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
    ):
        output = _git(*args, root=root).stdout
        working_paths.update(part.decode("utf-8") for part in output.split(b"\0") if part)
    unexpected_working = working_paths - EXCLUDED_FROM_TREE
    if unexpected_working:
        raise TranscriptError(
            f"working tree changes execution inputs: {sorted(unexpected_working)[:5]}"
        )


def _parse_tool_file(data: bytes) -> dict[str, tuple[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise TranscriptError("tool-hashes.txt is not UTF-8") from error
    pattern = re.compile(
        rf"tool-sha256: (?P<name>[a-z0-9-]+) (?P<hash>{HEX_64}) (?P<path>/\S+)"
    )
    if any(not pattern.fullmatch(line) for line in lines):
        raise TranscriptError("tool-hashes.txt contains a malformed line")
    return _parse_tools(lines, pattern)


def _memcheck_count(data: bytes, label: str) -> int:
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise TranscriptError(f"{label} Memcheck log is not UTF-8") from error
    matches = re.findall(r"ERROR SUMMARY: ([0-9][0-9,]*) errors", text)
    if len(matches) != 1:
        raise TranscriptError(f"{label} Memcheck log must contain exactly one ERROR SUMMARY")
    return int(matches[0].replace(",", ""))


def _bundle_file_set(bundle: pathlib.Path) -> set[str]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise TranscriptError("bundle path must be a non-symlink directory")
    files: set[str] = set()
    with os.scandir(bundle) as entries:
        for index, entry in enumerate(entries, start=1):
            if index > len(BUNDLE_ARTIFACTS) + 1:
                raise TranscriptError("bundle contains too many top-level entries")
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise TranscriptError(
                    f"bundle must be flat and contain only regular files: {entry.name}"
                )
            files.add(entry.name)
    return files


def _finalize_bundle(
    bundle: pathlib.Path,
    *,
    run_id: str,
    recorded_at: str,
    commit: str,
    execution_input_sha256: str,
    source_archive_sha256: str,
) -> str:
    if re.fullmatch(HEX_32, run_id) is None:
        raise TranscriptError("finalize run id is invalid")
    try:
        dt.datetime.strptime(recorded_at, "%Y-%m-%dT%H:%MZ")
    except ValueError as error:
        raise TranscriptError("finalize timestamp is invalid") from error
    for value, pattern, label in (
        (commit, HEX_40, "commit"),
        (execution_input_sha256, HEX_64, "execution-input digest"),
        (source_archive_sha256, HEX_64, "source archive digest"),
    ):
        if re.fullmatch(pattern, value) is None:
            raise TranscriptError(f"finalize {label} is invalid")
    actual = _bundle_file_set(bundle)
    expected = set(BUNDLE_ARTIFACTS.values())
    if actual != expected:
        raise TranscriptError(
            f"staged bundle file set mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    artifacts: dict[str, dict[str, str | int]] = {}
    total_size = 0
    for key, name in BUNDLE_ARTIFACTS.items():
        maximum = MAX_TEXT_ARTIFACT_BYTES if key in TEXT_ARTIFACTS else MAX_LARGE_ARTIFACT_BYTES
        size, digest = _hash_regular_file(bundle / name, maximum, key)
        total_size += size
        artifacts[key] = {"path": name, "sha256": digest, "size": size}
    if total_size > MAX_BUNDLE_BYTES:
        raise TranscriptError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    if artifacts["source_archive"]["sha256"] != source_archive_sha256:
        raise TranscriptError("staged source archive hash differs from the finalize argument")
    source_data = _read_regular_file(
        bundle / BUNDLE_ARTIFACTS["source_archive"],
        MAX_LARGE_ARTIFACT_BYTES,
        "source archive",
    )
    archive_digest = canonical_file_map_digest(
        {path: content for path, (content, _mode) in _archive_files(source_data).items()}
    )
    if archive_digest != execution_input_sha256:
        raise TranscriptError("staged source archive execution-input digest is invalid")
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "qperiapt-camera-ready-capture",
        "run_id": run_id,
        "recorded_at": recorded_at,
        "commit": commit,
        "execution_input_sha256": execution_input_sha256,
        "source_archive_sha256": source_archive_sha256,
        "netem_runs": 120,
        "ct_mode": "native",
        "generated_evidence_exclusions": sorted(EXCLUDED_FROM_TREE),
        "artifacts": artifacts,
    }
    data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    output = bundle / "manifest.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise TranscriptError("manifest write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def _verify_bundle(
    root: pathlib.Path, bundle: pathlib.Path, evidence: TranscriptEvidence
) -> None:
    expected_files = {"manifest.json", *BUNDLE_ARTIFACTS.values()}
    actual_files = _bundle_file_set(bundle)
    if actual_files != expected_files:
        raise TranscriptError(
            f"bundle file set mismatch: missing={sorted(expected_files - actual_files)}, "
            f"extra={sorted(actual_files - expected_files)}"
        )
    manifest_data = _read_regular_file(bundle / "manifest.json", MAX_MANIFEST_BYTES, "manifest")
    if hashlib.sha256(manifest_data).hexdigest() != evidence.bundle_manifest_sha256:
        raise TranscriptError("bundle manifest hash does not match transcript")
    manifest = _strict_json_bytes(manifest_data, "manifest")
    canonical_manifest = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if manifest_data != canonical_manifest:
        raise TranscriptError("bundle manifest is not canonical JSON")
    expected_manifest_keys = {
        "schema_version",
        "kind",
        "run_id",
        "recorded_at",
        "commit",
        "execution_input_sha256",
        "source_archive_sha256",
        "netem_runs",
        "ct_mode",
        "generated_evidence_exclusions",
        "artifacts",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_manifest_keys:
        raise TranscriptError("bundle manifest top-level key set is invalid")
    if type(manifest.get("schema_version")) is not int:
        raise TranscriptError("bundle manifest schema_version must be an integer")
    if type(manifest.get("netem_runs")) is not int:
        raise TranscriptError("bundle manifest netem_runs must be an integer")
    expected_values = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "qperiapt-camera-ready-capture",
        "run_id": evidence.run_id,
        "recorded_at": evidence.recorded_at,
        "commit": evidence.commit,
        "execution_input_sha256": evidence.execution_input_sha256,
        "source_archive_sha256": evidence.source_archive_sha256,
        "netem_runs": 120,
        "ct_mode": "native",
        "generated_evidence_exclusions": sorted(EXCLUDED_FROM_TREE),
    }
    for key, expected in expected_values.items():
        if manifest.get(key) != expected:
            raise TranscriptError(f"bundle manifest {key} is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(BUNDLE_ARTIFACTS):
        raise TranscriptError("bundle manifest artifact key set is invalid")
    total_size = len(manifest_data)
    for key, expected_path in BUNDLE_ARTIFACTS.items():
        record = artifacts[key]
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            raise TranscriptError(f"bundle artifact record is invalid: {key}")
        if not isinstance(record.get("path"), str):
            raise TranscriptError(f"bundle artifact path must be a string: {key}")
        if not isinstance(record.get("sha256"), str) or re.fullmatch(
            HEX_64, record["sha256"]
        ) is None:
            raise TranscriptError(f"bundle artifact sha256 is invalid: {key}")
        if type(record.get("size")) is not int or record["size"] < 0:
            raise TranscriptError(f"bundle artifact size must be a non-negative integer: {key}")
        if record.get("path") != expected_path:
            raise TranscriptError(f"bundle artifact path is invalid: {key}")
        maximum = MAX_TEXT_ARTIFACT_BYTES if key in TEXT_ARTIFACTS else MAX_LARGE_ARTIFACT_BYTES
        if record["size"] > maximum:
            raise TranscriptError(f"bundle artifact declared size exceeds its limit: {key}")
        total_size += record["size"]
    if total_size > MAX_BUNDLE_BYTES:
        raise TranscriptError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")

    data_by_key: dict[str, bytes] = {}
    actual_hashes: dict[str, str] = {}
    for key, expected_path in BUNDLE_ARTIFACTS.items():
        record = artifacts[key]
        maximum = MAX_TEXT_ARTIFACT_BYTES if key in TEXT_ARTIFACTS else MAX_LARGE_ARTIFACT_BYTES
        if key in BINARY_ARTIFACT_KEYS:
            actual_size, digest = _hash_regular_file(bundle / expected_path, maximum, key)
        else:
            data = _read_regular_file(bundle / expected_path, maximum, key)
            actual_size = len(data)
            digest = hashlib.sha256(data).hexdigest()
            data_by_key[key] = data
        if record.get("size") != actual_size:
            raise TranscriptError(f"bundle artifact size mismatch: {key}")
        if record.get("sha256") != digest:
            raise TranscriptError(f"bundle artifact hash mismatch: {key}")
        actual_hashes[key] = digest
    if hashlib.sha256(data_by_key["source_archive"]).hexdigest() != evidence.source_archive_sha256:
        raise TranscriptError("source archive hash differs from transcript")
    if actual_hashes["netem_binary"] != evidence.binary_hashes["netem"]:
        raise TranscriptError("netem binary hash differs from transcript")
    if actual_hashes["mlkem_ct_binary"] != evidence.binary_hashes["mlkem"]:
        raise TranscriptError("ML-KEM CT binary hash differs from transcript")
    if (
        actual_hashes["leaky_control_ct_binary"]
        != evidence.binary_hashes["leaky_control"]
    ):
        raise TranscriptError("synthetic leaky-control CT binary hash differs from transcript")

    archive_files = _archive_files(data_by_key["source_archive"])
    lock_entry = archive_files.get("Cargo.lock")
    if lock_entry is None:
        raise TranscriptError("source archive does not contain Cargo.lock")
    lock_data = lock_entry[0]
    seed = _parse_cargo_seed_manifest(data_by_key["cargo_seed_manifest"], lock_data)
    seed_hash = hashlib.sha256(data_by_key["cargo_seed_manifest"]).hexdigest()
    if (
        seed.package_count != evidence.cargo_seed_packages
        or seed.file_count != evidence.cargo_seed_files
        or seed_hash != evidence.cargo_seed_manifest_sha256
    ):
        raise TranscriptError("Cargo seed manifest differs from transcript")
    expected_capture_metadata = _capture_metadata_bytes(
        host_uname=evidence.host_uname,
        cpu=evidence.cpu,
        recorded_at=evidence.recorded_at,
        pin=evidence.pin,
        reps=evidence.reps,
        runner_user=evidence.runner_user,
        runner_uid=evidence.runner_uid,
        runner_gid=evidence.runner_gid,
        rustc_version=evidence.rustc_version,
        cargo_version=evidence.cargo_version,
        cc_version=evidence.cc_version,
        valgrind_version=evidence.valgrind_version,
        tuning_active_data=data_by_key["tuning_active"],
        tuning_after_data=data_by_key["tuning_after"],
        qdisc_baseline_data=data_by_key["qdisc_baseline"],
        qdisc_after_data=data_by_key["qdisc_after"],
        cargo_seed_manifest_data=data_by_key["cargo_seed_manifest"],
        lock_data=lock_data,
    )
    if data_by_key["capture_metadata"] != expected_capture_metadata:
        raise TranscriptError("capture metadata is noncanonical or differs from the transcript")

    _verify_source_provenance(root, data_by_key["source_archive"], evidence)
    tsv_rows = _parse_measurements_tsv(data_by_key["measurements"])
    if tsv_rows != evidence.measurements:
        raise TranscriptError("measurement TSV does not exactly match transcript rows")
    expected_summary = _canonical_summary_bytes(tsv_rows)
    if data_by_key["summary"] != expected_summary:
        raise TranscriptError("summary.json is not the canonical summary of measurements.tsv")
    if _strict_json_bytes(data_by_key["summary"], "summary") != measurement_summary(tsv_rows):
        raise TranscriptError("summary.json semantic content is invalid")
    if _parse_tool_file(data_by_key["tool_hashes"]) != evidence.tools:
        raise TranscriptError("tool hash file differs from transcript")
    validate_netem_bytes(data_by_key["qdisc_baseline"], 0)
    validate_netem_bytes(data_by_key["qdisc_10ms"], 10)
    validate_netem_bytes(data_by_key["qdisc_25ms"], 25)
    validate_netem_bytes(data_by_key["qdisc_after"], 0)

    for key in ("netem_build_log", "ct_build_log"):
        try:
            log = data_by_key[key].decode("utf-8")
        except UnicodeError as error:
            raise TranscriptError(f"{key} is not UTF-8") from error
        if re.search(r"(^|\s)(warning|error):", log, flags=re.IGNORECASE | re.MULTILINE):
            raise TranscriptError(f"{key} contains a warning or error")

    memcheck_keys = {
        "control": "memcheck_control",
        "ml-kem-ek": "memcheck_mlkem_ek",
        "ml-kem-wholedk": "memcheck_mlkem_wholedk",
        "ml-kem-probe": "memcheck_mlkem_probe",
        "leaky-control": "memcheck_leaky_control",
    }
    for label, key in memcheck_keys.items():
        if _memcheck_count(data_by_key[key], label) != evidence.memcheck_errors[label]:
            raise TranscriptError(f"{label} Memcheck log differs from transcript")


def _verify_freshness(
    recorded_at: str, max_age_seconds: int | None, now: dt.datetime | None
) -> None:
    if max_age_seconds is None:
        return
    if not 0 < max_age_seconds <= MAX_PROOF_AGE_SECONDS:
        raise TranscriptError(
            f"max proof age must be between 1 and {MAX_PROOF_AGE_SECONDS} seconds"
        )
    captured = dt.datetime.strptime(recorded_at, "%Y-%m-%dT%H:%MZ").replace(
        tzinfo=dt.timezone.utc
    )
    reference = now or dt.datetime.now(tz=dt.timezone.utc)
    age = (reference - captured).total_seconds()
    if age < -300:
        raise TranscriptError("capture timestamp is more than five minutes in the future")
    if age > max_age_seconds:
        raise TranscriptError("camera-ready capture is stale")


def verify_text(
    root: pathlib.Path,
    text: str,
    bundle: pathlib.Path,
    *,
    max_age_seconds: int | None = None,
    now: dt.datetime | None = None,
) -> None:
    """Verify a transcript and its raw bundle against current execution inputs."""

    if bundle.is_symlink():
        raise TranscriptError("bundle path must not be a symlink")
    evidence = _parse_transcript(text)
    _verify_freshness(evidence.recorded_at, max_age_seconds, now)
    _verify_bundle(root.resolve(), bundle.absolute(), evidence)


def verify_file(
    root: pathlib.Path,
    transcript: pathlib.Path,
    bundle: pathlib.Path,
    *,
    max_age_seconds: int | None = None,
) -> None:
    data = _read_regular_file(transcript, MAX_TRANSCRIPT_BYTES, "transcript")
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise TranscriptError("transcript is not UTF-8") from error
    verify_text(root, text, bundle, max_age_seconds=max_age_seconds)


def _write_summary(measurements: pathlib.Path, output: pathlib.Path) -> None:
    data = _read_regular_file(measurements, MAX_TEXT_ARTIFACT_BYTES, "measurements")
    rows = _parse_measurements_tsv(data)
    output.write_bytes(_canonical_summary_bytes(rows))


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True, type=pathlib.Path)
    verify_parser.add_argument("--transcript", required=True, type=pathlib.Path)
    verify_parser.add_argument("--bundle", required=True, type=pathlib.Path)
    verify_parser.add_argument("--max-age-seconds", type=int)
    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("--measurements", required=True, type=pathlib.Path)
    summary_parser.add_argument("--output", required=True, type=pathlib.Path)
    netem_parser = subparsers.add_parser("validate-netem")
    netem_parser.add_argument("--json", required=True, type=pathlib.Path)
    netem_parser.add_argument("--delay-ms", required=True, type=int, choices=(0, 10, 25))
    seed_parser = subparsers.add_parser("validate-cargo-seed")
    seed_parser.add_argument("--seed-home", required=True, type=pathlib.Path)
    seed_parser.add_argument("--lockfile", required=True, type=pathlib.Path)
    seed_parser.add_argument("--output", required=True, type=pathlib.Path)
    metadata_parser = subparsers.add_parser("write-capture-metadata")
    metadata_parser.add_argument("--output", required=True, type=pathlib.Path)
    metadata_parser.add_argument("--host-uname", required=True)
    metadata_parser.add_argument("--cpu", required=True)
    metadata_parser.add_argument("--recorded-at", required=True)
    metadata_parser.add_argument("--pin", required=True)
    metadata_parser.add_argument("--reps", required=True, type=int)
    metadata_parser.add_argument("--runner-user", required=True)
    metadata_parser.add_argument("--runner-uid", required=True, type=int)
    metadata_parser.add_argument("--runner-gid", required=True, type=int)
    metadata_parser.add_argument("--rustc-version", required=True)
    metadata_parser.add_argument("--cargo-version", required=True)
    metadata_parser.add_argument("--cc-version", required=True)
    metadata_parser.add_argument("--valgrind-version", required=True)
    metadata_parser.add_argument("--tuning-active", required=True, type=pathlib.Path)
    metadata_parser.add_argument("--tuning-after", required=True, type=pathlib.Path)
    metadata_parser.add_argument("--qdisc-baseline", required=True, type=pathlib.Path)
    metadata_parser.add_argument("--qdisc-after", required=True, type=pathlib.Path)
    metadata_parser.add_argument("--cargo-seed-manifest", required=True, type=pathlib.Path)
    metadata_parser.add_argument("--lockfile", required=True, type=pathlib.Path)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--bundle", required=True, type=pathlib.Path)
    finalize_parser.add_argument("--run-id", required=True)
    finalize_parser.add_argument("--recorded-at", required=True)
    finalize_parser.add_argument("--commit", required=True)
    finalize_parser.add_argument("--execution-input-sha256", required=True)
    finalize_parser.add_argument("--source-archive-sha256", required=True)
    freeze_parser = subparsers.add_parser("freeze-binary")
    freeze_parser.add_argument("--source", required=True, type=pathlib.Path)
    freeze_parser.add_argument("--output", required=True, type=pathlib.Path)
    freeze_parser.add_argument("--expected-uid", required=True, type=int)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            verify_file(
                args.root.resolve(),
                args.transcript.absolute(),
                args.bundle.absolute(),
                max_age_seconds=args.max_age_seconds,
            )
            print(
                "CAMERA_READY_BUNDLE_INTEGRITY_PASS "
                "boundary=producer_origin_not_independent_attestation"
            )
        elif args.command == "summarize":
            _write_summary(args.measurements.resolve(), args.output.resolve())
            print("CAMERA_READY_SUMMARY_PASS")
        elif args.command == "validate-netem":
            data = _read_regular_file(args.json.resolve(), MAX_TEXT_ARTIFACT_BYTES, "qdisc")
            validate_netem_bytes(data, args.delay_ms)
            print(f"CAMERA_READY_NETEM_JSON_PASS delay_ms={args.delay_ms}")
        elif args.command == "validate-cargo-seed":
            evidence = _write_cargo_seed_manifest(
                args.seed_home.absolute(), args.lockfile.absolute(), args.output.absolute()
            )
            manifest_data = _read_regular_file(
                args.output.absolute(), MAX_TEXT_ARTIFACT_BYTES, "Cargo seed manifest"
            )
            print(
                f"CAMERA_READY_CARGO_SEED_PASS packages={evidence.package_count} "
                f"files={evidence.file_count} "
                f"manifest_sha256={hashlib.sha256(manifest_data).hexdigest()}"
            )
        elif args.command == "write-capture-metadata":
            _write_capture_metadata(
                args.output.absolute(),
                host_uname=args.host_uname,
                cpu=args.cpu,
                recorded_at=args.recorded_at,
                pin=args.pin,
                reps=args.reps,
                runner_user=args.runner_user,
                runner_uid=args.runner_uid,
                runner_gid=args.runner_gid,
                rustc_version=args.rustc_version,
                cargo_version=args.cargo_version,
                cc_version=args.cc_version,
                valgrind_version=args.valgrind_version,
                tuning_active_data=_read_regular_file(
                    args.tuning_active.absolute(), MAX_TEXT_ARTIFACT_BYTES, "tuning active"
                ),
                tuning_after_data=_read_regular_file(
                    args.tuning_after.absolute(), MAX_TEXT_ARTIFACT_BYTES, "tuning after"
                ),
                qdisc_baseline_data=_read_regular_file(
                    args.qdisc_baseline.absolute(), MAX_TEXT_ARTIFACT_BYTES, "qdisc baseline"
                ),
                qdisc_after_data=_read_regular_file(
                    args.qdisc_after.absolute(), MAX_TEXT_ARTIFACT_BYTES, "qdisc after"
                ),
                cargo_seed_manifest_data=_read_regular_file(
                    args.cargo_seed_manifest.absolute(),
                    MAX_TEXT_ARTIFACT_BYTES,
                    "Cargo seed manifest",
                ),
                lock_data=_read_regular_file(
                    args.lockfile.absolute(), MAX_TEXT_ARTIFACT_BYTES, "Cargo.lock"
                ),
            )
            print("CAMERA_READY_CAPTURE_METADATA_PASS")
        elif args.command == "finalize":
            digest = _finalize_bundle(
                args.bundle.absolute(),
                run_id=args.run_id,
                recorded_at=args.recorded_at,
                commit=args.commit,
                execution_input_sha256=args.execution_input_sha256,
                source_archive_sha256=args.source_archive_sha256,
            )
            print(f"CAMERA_READY_BUNDLE_FINALIZED manifest_sha256={digest}")
        else:
            digest = _freeze_binary(
                args.source.absolute(), args.output.absolute(), args.expected_uid
            )
            print(f"CAMERA_READY_BINARY_FROZEN sha256={digest}")
    except (
        LedgerError,
        OSError,
        TranscriptError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"error: camera-ready proof verification failed: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
