#!/usr/bin/env python3
"""Fail-closed Android ABI2 ELF and AAR release verification."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from typing import Any, Iterable

from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from evidence_io import EvidenceIOError, FileSnapshot, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import (
    GitProvenanceError,
    inspect_worktree,
    require_commit_or_evidence_successor,
    run_git_text,
)
from release_binary_scan import ReleaseBinaryScanError, scan_release_file
from third_party_licenses import (
    ThirdPartyLicenseError,
    canonical_json as canonical_license_inventory_json,
    verify as verify_third_party_licenses,
)


FFI_LIBRARY = "libq_periapt_ffi_abi2.so"
JNI_LIBRARY = "libqperiapt_jni_abi2.so"
FFI_EXPORTS = frozenset(
    {
        "q_periapt_abi_version",
        "q_periapt_decapsulate",
        "q_periapt_decision_from_signed_policy",
        "q_periapt_encapsulate",
        "q_periapt_fixed_suite_id",
        "q_periapt_fixed_suite_id_len",
        "q_periapt_generate_keypair",
        "q_periapt_status_name",
        "q_periapt_version",
    }
)
JNI_EXPORTS = frozenset({"JNI_OnLoad"})
LEGACY_LIBRARIES = frozenset({"libq_periapt_ffi.so", "libqperiapt_jni.so"})
SYSTEM_NEEDED_ALLOWLIST = frozenset(
    {
        "libandroid.so",
        "libc.so",
        "libdl.so",
        "libgcc.so",
        "liblog.so",
        "libm.so",
        "libunwind.so",
    }
)
MIN_LOAD_ALIGNMENT = 0x4000
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 128 * 1024 * 1024
MAX_CLASSES_JAR_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class AbiSpec:
    elf_class: int
    machine: int
    machine_name: str


ABI_SPECS = {
    "arm64-v8a": AbiSpec(elf_class=2, machine=183, machine_name="AArch64"),
    "x86_64": AbiSpec(elf_class=2, machine=62, machine_name="Advanced Micro Devices X86-64"),
    "armeabi-v7a": AbiSpec(elf_class=1, machine=40, machine_name="ARM"),
    "x86": AbiSpec(elf_class=1, machine=3, machine_name="Intel 80386"),
}
REQUIRED_ABIS = tuple(ABI_SPECS)

MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "package",
        "version",
        "generated_at",
        "source_date_epoch",
        "git_commit",
        "git_dirty",
        "diagnostic_only",
        "source_tree_sha256",
        "package_only",
        "device_runtime_proof",
        "boundary",
        "third_party",
        "abi",
        "android",
        "artifacts",
    }
)
MANIFEST_ABI_FIELDS = frozenset(
    {
        "major",
        "contract_path",
        "contract_sha256",
        "exports_sha256",
        "export_count",
        "platform",
        "runtime_identity",
        "shared_filename",
        "static_filename",
    }
)
MANIFEST_RUNTIME_IDENTITY_FIELDS = frozenset(
    {"abis", "jni_library", "loader_order", "runtime_library"}
)
MANIFEST_ANDROID_FIELDS = frozenset(
    {
        "sdk",
        "ndk",
        "platform",
        "build_tools",
        "min_sdk",
        "native_page_alignment",
        "native_stripped",
        "abis",
    }
)
MANIFEST_ARTIFACT_FIELDS = frozenset(
    {
        "aar_sha256",
        "classes_jar_sha256",
        "java_facade_sha256",
        "jni_adapter_sha256",
        "script_sha256",
        "elf_verifier_sha256",
        "release_binary_scan_sha256",
        "third_party_license_collector_sha256",
        "native",
    }
)
MANIFEST_NATIVE_HASH_FIELDS = frozenset({"ffi_so_sha256", "jni_so_sha256"})


def _native_entries() -> set[str]:
    return {
        f"jni/{abi}/{library}"
        for abi in REQUIRED_ABIS
        for library in (FFI_LIBRARY, JNI_LIBRARY)
    }


REQUIRED_AAR_ENTRIES = frozenset(
    {
        "AndroidManifest.xml",
        "classes.jar",
        "R.txt",
        "proguard.txt",
        "META-INF/LICENSE",
        "META-INF/LICENSES/Apache-2.0.txt",
        "META-INF/LICENSES/MIT.txt",
        *_native_entries(),
    }
)
THIRD_PARTY_RUST_PREFIX = "META-INF/THIRD_PARTY/rust/"
THIRD_PARTY_RUST_INVENTORY = THIRD_PARTY_RUST_PREFIX + "INVENTORY.json"
THIRD_PARTY_RUST_TARGET = "x86_64-linux-android"
THIRD_PARTY_RUST_COVERED_TARGETS = (
    "aarch64-linux-android",
    "x86_64-linux-android",
    "armv7-linux-androideabi",
    "i686-linux-android",
)


class AndroidVerificationError(RuntimeError):
    """A release invariant was not proven."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AndroidVerificationError(message)


def exact_object(
    value: Any,
    expected_fields: frozenset[str] | set[str],
    label: str,
) -> dict[str, Any]:
    require(
        isinstance(value, dict) and set(value) == set(expected_fields),
        f"{label} fields differ",
    )
    return value


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_expected_git_commit(expected: str, actual: str) -> None:
    require(
        re.fullmatch(r"[0-9a-f]{40,64}", actual) is not None,
        "actual Android source commit is malformed",
    )
    if expected == "":
        return
    require(
        re.fullmatch(r"[0-9a-f]{40}", expected) is not None,
        "QPERIAPT_EXPECTED_GIT_COMMIT must be exactly 40 lowercase hexadecimal characters",
    )
    require(
        hmac.compare_digest(expected, actual),
        "QPERIAPT_EXPECTED_GIT_COMMIT differs from the Android source commit",
    )


def verify_ndk_r29(ndk: pathlib.Path) -> str:
    properties = ndk / "source.properties"
    require_regular_file(properties, "Android NDK source.properties")
    try:
        text = properties.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AndroidVerificationError(f"cannot read Android NDK metadata {properties}: {exc}") from exc
    match = re.search(r"^Pkg\.Revision\s*=\s*([^\s]+)\s*$", text, re.MULTILINE)
    require(match is not None, f"Android NDK revision missing from {properties}")
    revision = match.group(1)
    require(revision.startswith("29."), f"Android ABI2 release requires NDK r29, got {revision} at {ndk}")
    return revision


def find_ndk_toolchain(ndk: pathlib.Path) -> pathlib.Path:
    verify_ndk_r29(ndk)
    prebuilt = ndk / "toolchains" / "llvm" / "prebuilt"
    require(prebuilt.is_dir() and not prebuilt.is_symlink(), f"NDK LLVM prebuilt directory is unsafe or missing: {prebuilt}")
    candidates = [
        candidate
        for candidate in sorted(prebuilt.iterdir())
        if candidate.is_dir()
        and not candidate.is_symlink()
        and (candidate / "bin" / "llvm-nm").is_file()
        and (candidate / "bin" / "llvm-readelf").exists()
        and (candidate / "sysroot" / "usr" / "include" / "jni.h").is_file()
    ]
    require(len(candidates) == 1, f"expected exactly one usable NDK r29 LLVM toolchain under {prebuilt}, got {candidates}")
    return candidates[0]


def require_regular_file(path: pathlib.Path, label: str, *, executable: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AndroidVerificationError(f"cannot inspect {label} {path}: {exc}") from exc
    require(stat.S_ISREG(info.st_mode), f"{label} must be a regular non-symlink file: {path}")
    if executable:
        require(os.access(path, os.X_OK), f"{label} is not executable: {path}")


def run_tool(tool: pathlib.Path, arguments: list[str], subject: pathlib.Path) -> str:
    """Run a verifier tool without allowing output to mask a failing exit status."""

    try:
        resolved_tool = tool.resolve(strict=True)
    except OSError as exc:
        raise AndroidVerificationError(f"cannot resolve verification tool {tool}: {exc}") from exc
    require_regular_file(resolved_tool, "verification tool", executable=True)
    try:
        completed = subprocess.run(
            [str(tool), *arguments, str(subject)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError) as exc:
        raise AndroidVerificationError(f"cannot execute {tool} for {subject}: {exc}") from exc
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        detail = f": {stderr}" if stderr else ""
        raise AndroidVerificationError(
            f"{tool.name} failed for {subject} with exit status {completed.returncode}{detail}"
        )
    require(not stderr, f"{tool.name} emitted diagnostics for {subject}: {stderr}")
    return completed.stdout


def parse_elf_header(path: pathlib.Path, abi: str) -> None:
    require_regular_file(path, f"{abi} ELF")
    try:
        with path.open("rb") as source:
            header = source.read(64)
    except OSError as exc:
        raise AndroidVerificationError(f"cannot read ELF header from {path}: {exc}") from exc
    require(len(header) >= 20, f"truncated ELF header: {path}")
    require(header[:4] == b"\x7fELF", f"invalid ELF magic: {path}")
    spec = ABI_SPECS[abi]
    require(header[4] == spec.elf_class, f"{abi} has wrong ELF class in {path}: {header[4]}")
    require(header[5] == 1, f"{abi} ELF must be little-endian: {path}")
    require(header[6] == 1, f"{abi} ELF has unsupported identification version: {path}")
    byte_order = "little"
    elf_type = int.from_bytes(header[16:18], byte_order)
    machine = int.from_bytes(header[18:20], byte_order)
    require(elf_type == 3, f"{abi} ELF must be ET_DYN, got e_type={elf_type}: {path}")
    require(
        machine == spec.machine,
        f"{abi} has wrong ELF machine in {path}: got {machine}, expected {spec.machine} ({spec.machine_name})",
    )


def parse_nm_exports(output: str, path: pathlib.Path) -> frozenset[str]:
    symbols: list[str] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        fields = line.split()
        require(len(fields) >= 2, f"malformed llvm-nm output for {path} at line {line_number}: {line!r}")
        symbols.append(fields[0])
    require(len(symbols) == len(set(symbols)), f"duplicate exported symbol reported for {path}")
    return frozenset(symbols)


def parse_dynamic_entries(output: str, path: pathlib.Path) -> tuple[str, frozenset[str], set[str], dict[str, str]]:
    tags: dict[str, list[str]] = {}
    dynamic_line = re.compile(r"^\s*0x[0-9a-fA-F]+\s+\(([^)]+)\)\s+(.*?)\s*$")
    for line in output.splitlines():
        match = dynamic_line.match(line)
        if match:
            tags.setdefault(match.group(1), []).append(match.group(2))

    sonames = tags.get("SONAME", [])
    require(len(sonames) == 1, f"{path} must contain exactly one SONAME dynamic entry")
    soname_match = re.search(r"\[([^\]]+)\]", sonames[0])
    require(soname_match is not None, f"cannot parse SONAME for {path}: {sonames[0]!r}")

    needed: list[str] = []
    for value in tags.get("NEEDED", []):
        needed_match = re.search(r"\[([^\]]+)\]", value)
        require(needed_match is not None, f"cannot parse NEEDED entry for {path}: {value!r}")
        needed.append(needed_match.group(1))
    require(len(needed) == len(set(needed)), f"duplicate NEEDED entry in {path}")
    flat_tags = {name: " ".join(values) for name, values in tags.items()}
    return soname_match.group(1), frozenset(needed), set(tags), flat_tags


def verify_program_headers(output: str, path: pathlib.Path) -> None:
    load_alignments: list[int] = []
    relro_count = 0
    stack_flags: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "LOAD":
            try:
                load_alignments.append(int(fields[-1], 0))
            except (ValueError, IndexError) as exc:
                raise AndroidVerificationError(f"cannot parse LOAD alignment for {path}: {line!r}") from exc
        elif fields[0] == "GNU_RELRO":
            relro_count += 1
        elif fields[0] == "GNU_STACK":
            require(len(fields) >= 8, f"cannot parse GNU_STACK header for {path}: {line!r}")
            stack_flags.append("".join(fields[6:-1]))

    require(load_alignments, f"{path} has no LOAD program headers")
    too_small = [alignment for alignment in load_alignments if alignment < MIN_LOAD_ALIGNMENT]
    require(
        not too_small,
        f"{path} has LOAD alignment below 16 KiB: {', '.join(hex(value) for value in too_small)}",
    )
    require(relro_count == 1, f"{path} must contain exactly one GNU_RELRO program header")
    require(len(stack_flags) == 1, f"{path} must contain exactly one GNU_STACK program header")
    require("E" not in stack_flags[0], f"{path} requests an executable stack: {stack_flags[0]}")


def verify_release_sections(output: str, path: pathlib.Path) -> None:
    section_names = set(re.findall(r"^\s*\[\s*\d+\]\s+(\S+)", output, re.MULTILINE))
    require(section_names, f"cannot parse ELF section table for {path}")
    prohibited = sorted(
        name
        for name in section_names
        if name in {".symtab", ".strtab"} or name.startswith((".debug", ".zdebug"))
    )
    require(not prohibited, f"{path} contains unstripped release sections: {', '.join(prohibited)}")


def verify_dynamic_policy(output: str, path: pathlib.Path, library: str) -> None:
    soname, needed, tag_names, tag_values = parse_dynamic_entries(output, path)
    require(soname == library, f"{path} SONAME mismatch: got {soname}, expected {library}")
    prohibited = sorted(tag_names.intersection({"TEXTREL", "RPATH", "RUNPATH"}))
    require(not prohibited, f"{path} contains prohibited dynamic tags: {', '.join(prohibited)}")
    require(
        "BIND_NOW" in tag_values.get("FLAGS", "") or re.search(r"(?:^|\s)NOW(?:\s|$)", tag_values.get("FLAGS_1", "")) is not None,
        f"{path} does not enable immediate binding (NOW)",
    )
    require(not needed.intersection(LEGACY_LIBRARIES), f"{path} depends on an ABI1 library")
    project_needed = needed.difference(SYSTEM_NEEDED_ALLOWLIST)
    if library == FFI_LIBRARY:
        require(not project_needed, f"{path} has unexpected non-system dependencies: {sorted(project_needed)}")
    else:
        require(
            project_needed == {FFI_LIBRARY},
            f"{path} project dependencies must be exactly {FFI_LIBRARY}: got {sorted(project_needed)}",
        )


def verify_library(
    path: pathlib.Path,
    *,
    abi: str,
    library: str,
    llvm_nm: pathlib.Path,
    llvm_readelf: pathlib.Path,
) -> None:
    require(abi in ABI_SPECS, f"unsupported Android ABI: {abi}")
    require(library in {FFI_LIBRARY, JNI_LIBRARY}, f"unsupported Android library: {library}")
    require(path.name == library, f"Android native filename mismatch: {path.name}, expected {library}")
    parse_elf_header(path, abi)
    nm_output = run_tool(llvm_nm, ["-D", "--defined-only", "--format=posix"], path)
    exports = parse_nm_exports(nm_output, path)
    expected_exports = FFI_EXPORTS if library == FFI_LIBRARY else JNI_EXPORTS
    require(
        exports == expected_exports,
        f"{abi} {library} exports differ from the exact allowlist: got {sorted(exports)}, expected {sorted(expected_exports)}",
    )
    readelf_output = run_tool(llvm_readelf, ["-h", "-l", "-d", "-S", "-W"], path)
    verify_program_headers(readelf_output, path)
    verify_release_sections(readelf_output, path)
    verify_dynamic_policy(readelf_output, path, library)


def verify_native_tree(
    root: pathlib.Path,
    *,
    llvm_nm: pathlib.Path,
    llvm_readelf: pathlib.Path,
) -> None:
    require(root.is_dir() and not root.is_symlink(), f"Android AAR stage must be a non-symlink directory: {root}")
    jni_root = root / "jni"
    require(jni_root.is_dir() and not jni_root.is_symlink(), f"Android AAR stage lacks a safe jni directory: {jni_root}")
    actual = {
        path.relative_to(root).as_posix()
        for path in jni_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    expected = _native_entries()
    require(actual == expected, f"staged native file set mismatch: got {sorted(actual)}, expected {sorted(expected)}")
    for abi in REQUIRED_ABIS:
        for library in (FFI_LIBRARY, JNI_LIBRARY):
            verify_library(
                jni_root / abi / library,
                abi=abi,
                library=library,
                llvm_nm=llvm_nm,
                llvm_readelf=llvm_readelf,
            )


def _validate_zip_name(name: str, *, label: str) -> None:
    require(name != "", f"{label} contains an empty entry name")
    require("\x00" not in name, f"{label} entry contains NUL: {name!r}")
    require("\\" not in name, f"{label} entry contains a backslash: {name!r}")
    require(not name.startswith("/"), f"{label} entry is absolute: {name!r}")
    normalized = pathlib.PurePosixPath(name)
    require(".." not in normalized.parts, f"{label} entry traverses a parent: {name!r}")
    require(normalized.as_posix() == name, f"{label} entry is not canonically named: {name!r}")


def _read_zip_entries(
    archive: zipfile.ZipFile,
    *,
    label: str,
    max_total_bytes: int,
    max_entry_bytes: int,
) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    casefold_names: dict[str, str] = {}
    advertised_total = 0
    for info in archive.infolist():
        name = info.filename
        _validate_zip_name(name, label=label)
        require(name not in entries, f"{label} contains duplicate entry: {name}")
        previous = casefold_names.get(name.casefold())
        require(previous is None, f"{label} contains case-conflicting entries: {previous!r}, {name!r}")
        casefold_names[name.casefold()] = name
        mode = (info.external_attr >> 16) & 0o177777
        require(not name.endswith("/"), f"{label} must not contain directory entries: {name}")
        require(mode in {0, 0o100600, 0o100644}, f"{label} contains unsafe file mode for {name}: {oct(mode)}")
        require(info.flag_bits & 0x1 == 0, f"{label} contains encrypted entry: {name}")
        require(info.file_size <= max_entry_bytes, f"{label} entry is too large: {name}")
        advertised_total += info.file_size
        require(advertised_total <= max_total_bytes, f"{label} uncompressed size exceeds the release limit")
        try:
            data = archive.read(info)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise AndroidVerificationError(f"cannot read {label} entry {name} with CRC verification: {exc}") from exc
        require(len(data) == info.file_size, f"{label} entry size mismatch after extraction: {name}")
        entries[name] = data
    return entries


def audit_classes_jar(data: bytes) -> dict[str, bytes]:
    require(len(data) <= MAX_CLASSES_JAR_BYTES, "classes.jar exceeds the release size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = _read_zip_entries(
                archive,
                label="classes.jar",
                max_total_bytes=MAX_CLASSES_JAR_BYTES,
                max_entry_bytes=MAX_CLASSES_JAR_BYTES,
            )
    except zipfile.BadZipFile as exc:
        raise AndroidVerificationError(f"classes.jar is not a valid ZIP archive: {exc}") from exc
    require(entries, "classes.jar is empty")
    primary_class = "dev/qperiapt/android/QPeriaptAndroid.class"
    require(primary_class in entries, f"classes.jar lacks {primary_class}")
    for name in entries:
        require(
            name.startswith("dev/qperiapt/android/") and name.endswith(".class"),
            f"classes.jar contains an unexpected entry: {name}",
        )
        require(
            not name.lower().endswith((".aar", ".dex", ".jar", ".so", ".zip")),
            f"classes.jar contains a nested executable/archive: {name}",
        )
        require(entries[name].startswith(b"\xca\xfe\xba\xbe"), f"classes.jar entry is not a JVM class file: {name}")
    return entries


def audit_third_party_license_entries(entries: dict[str, bytes]) -> dict[str, Any]:
    actual = frozenset(entries)
    missing = REQUIRED_AAR_ENTRIES - actual
    unexpected = {
        name
        for name in actual - REQUIRED_AAR_ENTRIES
        if not name.startswith(THIRD_PARTY_RUST_PREFIX)
    }
    require(
        not missing and not unexpected,
        "Android AAR file set mismatch: "
        f"missing={sorted(missing)}, unexpected={sorted(unexpected)}",
    )
    require(
        THIRD_PARTY_RUST_INVENTORY in entries,
        f"Android AAR lacks {THIRD_PARTY_RUST_INVENTORY}",
    )
    license_entries = {
        name: data
        for name, data in entries.items()
        if name.startswith(THIRD_PARTY_RUST_PREFIX)
    }
    with tempfile.TemporaryDirectory(prefix="qperiapt-android-licenses-") as temp:
        package_root = pathlib.Path(temp) / "META-INF"
        try:
            for name, data in license_entries.items():
                relative = pathlib.PurePosixPath(name).relative_to("META-INF")
                output = package_root / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(data)
            inventory = verify_third_party_licenses(
                package_root,
                expected_target=THIRD_PARTY_RUST_TARGET,
            )
        except (OSError, ThirdPartyLicenseError) as exc:
            raise AndroidVerificationError(
                f"Android AAR third-party Rust license verification failed: {exc}"
            ) from exc
    require(
        entries[THIRD_PARTY_RUST_INVENTORY]
        == canonical_license_inventory_json(inventory),
        "Android AAR third-party Rust inventory bytes are not canonical",
    )
    return inventory


def audit_aar_bytes(data: bytes, *, label: str) -> tuple[dict[str, bytes], dict[str, bytes]]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = _read_zip_entries(
                archive,
                label="Android AAR",
                max_total_bytes=MAX_ARCHIVE_BYTES,
                max_entry_bytes=MAX_ARCHIVE_ENTRY_BYTES,
            )
    except zipfile.BadZipFile as exc:
        raise AndroidVerificationError(f"Android AAR is not a valid ZIP archive: {label}: {exc}") from exc
    audit_third_party_license_entries(entries)
    classes = audit_classes_jar(entries["classes.jar"])
    return entries, classes


def read_snapshot(path: pathlib.Path, *, maximum: int, label: str) -> FileSnapshot:
    try:
        return read_regular_snapshot(path, maximum=maximum, label=label)
    except EvidenceIOError as exc:
        raise AndroidVerificationError(str(exc)) from exc


def audit_aar(path: pathlib.Path) -> tuple[dict[str, bytes], dict[str, bytes]]:
    snapshot = read_snapshot(path, maximum=MAX_ARCHIVE_BYTES, label="Android AAR")
    return audit_aar_bytes(snapshot.data, label=str(snapshot.path))


def scan_release_paths(paths: Iterable[pathlib.Path], *, forbidden_text: Iterable[str]) -> None:
    for path in paths:
        try:
            scan_release_file(path, forbidden_text=forbidden_text)
        except ReleaseBinaryScanError as exc:
            raise AndroidVerificationError(str(exc)) from exc


def extract_verified_entries(entries: dict[str, bytes], destination: pathlib.Path) -> None:
    require(destination.is_absolute(), f"AAR extraction destination must be absolute: {destination}")
    parent = destination.parent
    require(parent.is_dir() and not parent.is_symlink(), f"AAR extraction parent is unsafe or missing: {parent}")
    require(not destination.exists() and not destination.is_symlink(), f"AAR extraction destination already exists: {destination}")
    try:
        staging = pathlib.Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    except OSError as exc:
        raise AndroidVerificationError(f"cannot create temporary AAR extraction directory under {parent}: {exc}") from exc
    try:
        for name, data in entries.items():
            output = staging / pathlib.PurePosixPath(name)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        os.replace(staging, destination)
    except OSError as exc:
        try:
            shutil.rmtree(staging)
        except OSError as cleanup_exc:
            exc.add_note(f"cleaning the partial AAR extraction also failed: {cleanup_exc}")
        raise AndroidVerificationError(f"cannot atomically extract verified AAR snapshot to {destination}: {exc}") from exc


def _strict_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = parse_strict_json_bytes(data, label=label)
    except EvidenceIOError as exc:
        raise AndroidVerificationError(f"cannot parse {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label} root must be a JSON object")
    return value


def verify_manifest_source_provenance(
    manifest: dict[str, Any],
    *,
    source_root: pathlib.Path,
    require_release: bool,
) -> None:
    """Verify deterministic source provenance recorded by an AAR manifest."""

    source_commit = manifest.get("git_commit")
    require(
        isinstance(source_commit, str)
        and re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is not None,
        "Android AAR manifest git_commit is malformed",
    )
    source_dirty = manifest.get("git_dirty")
    require(type(source_dirty) is bool, "Android AAR manifest git_dirty must be a boolean")
    diagnostic_only = manifest.get("diagnostic_only")
    require(
        type(diagnostic_only) is bool and diagnostic_only is source_dirty,
        "Android AAR manifest diagnostic_only must exactly match git_dirty",
    )
    source_epoch = manifest.get("source_date_epoch")
    require(
        type(source_epoch) is int and 0 <= source_epoch <= 0xFFFFFFFF,
        "Android AAR manifest source_date_epoch must be an unsigned 32-bit integer",
    )
    generated_at = manifest.get("generated_at")
    expected_generated_at = (
        dt.datetime.fromtimestamp(source_epoch, tz=dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    require(
        generated_at == expected_generated_at,
        "Android AAR manifest generated_at must exactly equal source_date_epoch",
    )
    source_tree_sha256 = manifest.get("source_tree_sha256")
    require(
        isinstance(source_tree_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", source_tree_sha256) is not None,
        "Android AAR manifest source_tree_sha256 is malformed",
    )

    try:
        require_commit_or_evidence_successor(source_root, source_commit)
        commit_epoch = run_git_text(
            source_root,
            ["show", "-s", "--format=%ct", source_commit],
        )
        inspection = inspect_worktree(source_root)
        actual_source_tree_sha256 = canonical_tree_digest(
            source_root,
            repository_paths(source_root),
        )
    except (GitProvenanceError, LedgerError, OSError, UnicodeDecodeError) as exc:
        raise AndroidVerificationError(
            f"cannot verify Android AAR source provenance: {exc}"
        ) from exc
    require(
        commit_epoch.isascii() and commit_epoch.isdigit(),
        "Android AAR source commit epoch is malformed",
    )
    require(
        int(commit_epoch) == source_epoch,
        "Android AAR manifest source_date_epoch differs from its source commit",
    )
    require(
        inspection.dirty is source_dirty,
        "Android AAR manifest git_dirty differs from the current source tree",
    )
    require(
        actual_source_tree_sha256 == source_tree_sha256,
        "Android AAR manifest source tree digest differs from current source bytes",
    )
    if require_release:
        require(source_dirty is False, "release Android AAR manifest must come from a clean tree")
        require(
            diagnostic_only is False,
            "release Android AAR manifest must not be diagnostic_only",
        )


def verify_manifest(
    path: pathlib.Path,
    *,
    aar_path: pathlib.Path,
    entries: dict[str, bytes],
    aar_sha256: str,
    expected_manifest_sha256: str | None,
    require_release: bool,
    forbidden_text: Iterable[str],
    source_root: pathlib.Path,
) -> None:
    snapshot = read_snapshot(path, maximum=16 * 1024 * 1024, label="Android AAR manifest")
    with tempfile.TemporaryDirectory(prefix="qperiapt-android-manifest-") as temp:
        scan_path = pathlib.Path(temp) / "MANIFEST.json"
        try:
            scan_path.write_bytes(snapshot.data)
        except OSError as exc:
            raise AndroidVerificationError(f"cannot materialize Android manifest for scanning: {exc}") from exc
        scan_release_paths([scan_path], forbidden_text=forbidden_text)
    if expected_manifest_sha256 is not None:
        require(re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) is not None, "invalid expected manifest SHA-256")
        require(
            hmac.compare_digest(snapshot.sha256, expected_manifest_sha256),
            f"Android AAR manifest SHA-256 mismatch: {path}",
        )
    manifest = _strict_json_object(snapshot.data, label="Android AAR manifest")
    require(
        snapshot.data == canonical_json(manifest),
        "Android AAR manifest bytes are not canonical JSON",
    )
    exact_object(manifest, MANIFEST_FIELDS, "Android AAR manifest")
    require(manifest.get("schema_version") == 3, "Android AAR manifest schema must be 3")
    require(manifest.get("kind") == "qperiapt.android_aar_manifest", "unexpected Android AAR manifest kind")
    require(manifest.get("package") == aar_path.name, "Android AAR manifest package filename mismatch")
    require(manifest.get("version") == "0.1.0-alpha.2", "Android AAR manifest version mismatch")
    require(manifest.get("package_only") is True, "Android AAR manifest must be package_only")
    require(manifest.get("device_runtime_proof") is False, "AAR package manifest must not claim device runtime proof")
    require(
        manifest.get("boundary")
        == "AAR/JNI packaging proof only; Android emulator or physical-device instrumentation is required before claiming Android runtime readiness.",
        "Android AAR manifest boundary statement differs",
    )
    verify_manifest_source_provenance(
        manifest,
        source_root=source_root,
        require_release=require_release,
    )
    inventory = audit_third_party_license_entries(entries)
    third_party = manifest.get("third_party")
    require(
        isinstance(third_party, dict) and set(third_party) == {"rust"},
        "Android AAR manifest third_party fields differ",
    )
    rust_licenses = third_party.get("rust")
    require(
        isinstance(rust_licenses, dict)
        and set(rust_licenses)
        == {
            "covered_targets",
            "inventory_path",
            "inventory_sha256",
            "package_count",
            "target",
        },
        "Android AAR manifest Rust license fields differ",
    )
    require(
        rust_licenses.get("inventory_path") == THIRD_PARTY_RUST_INVENTORY,
        "Android AAR manifest Rust license inventory path mismatch",
    )
    require(
        rust_licenses.get("inventory_sha256")
        == sha256_bytes(entries[THIRD_PARTY_RUST_INVENTORY]),
        "Android AAR manifest Rust license inventory hash mismatch",
    )
    require(
        rust_licenses.get("package_count") == len(inventory["packages"]),
        "Android AAR manifest Rust license package count mismatch",
    )
    require(
        rust_licenses.get("target") == THIRD_PARTY_RUST_TARGET,
        "Android AAR manifest Rust license target mismatch",
    )
    require(
        rust_licenses.get("covered_targets")
        == list(THIRD_PARTY_RUST_COVERED_TARGETS),
        "Android AAR manifest Rust license covered-target list mismatch",
    )

    abi = exact_object(
        manifest.get("abi"), MANIFEST_ABI_FIELDS, "Android AAR manifest ABI"
    )
    require(abi.get("major") == 2, "Android AAR manifest ABI major mismatch")
    require(abi.get("export_count") == len(FFI_EXPORTS), "Android AAR manifest export count mismatch")
    exports_digest = sha256_bytes(("\n".join(sorted(FFI_EXPORTS)) + "\n").encode("utf-8"))
    require(abi.get("exports_sha256") == exports_digest, "Android AAR manifest export-set digest mismatch")
    require(abi.get("platform") == "android-aar", "Android AAR manifest ABI platform mismatch")
    require(abi.get("shared_filename") == FFI_LIBRARY, "Android AAR manifest shared filename mismatch")
    require(abi.get("static_filename") == "not-shipped-abi2", "Android AAR manifest static filename mismatch")
    runtime = exact_object(
        abi.get("runtime_identity"),
        MANIFEST_RUNTIME_IDENTITY_FIELDS,
        "Android AAR manifest runtime identity",
    )
    require(runtime.get("abis") == list(REQUIRED_ABIS), "Android AAR manifest ABI list/order mismatch")
    require(runtime.get("runtime_library") == FFI_LIBRARY, "Android AAR runtime library mismatch")
    require(runtime.get("jni_library") == JNI_LIBRARY, "Android AAR JNI library mismatch")
    require(
        runtime.get("loader_order")
        == ["q_periapt_ffi_abi2", "qperiapt_jni_abi2"],
        "Android AAR loader order mismatch",
    )

    android = exact_object(
        manifest.get("android"),
        MANIFEST_ANDROID_FIELDS,
        "Android AAR manifest Android metadata",
    )
    require(android.get("sdk") == "local-android-sdk", "Android AAR manifest SDK label mismatch")
    require(android.get("abis") == list(REQUIRED_ABIS), "Android AAR manifest Android ABI list/order mismatch")
    require(android.get("min_sdk") == 23, "Android AAR manifest minimum SDK mismatch")
    require(android.get("native_page_alignment") == MIN_LOAD_ALIGNMENT, "Android AAR manifest lacks 16 KiB native alignment metadata")
    require(android.get("native_stripped") is True, "Android AAR manifest must record stripped native libraries")
    ndk = android.get("ndk")
    require(
        isinstance(ndk, str) and re.fullmatch(r"29\.[0-9]+\.[0-9]+", ndk) is not None,
        f"Android AAR manifest must use NDK r29, got {ndk!r}",
    )
    platform = android.get("platform")
    require(
        isinstance(platform, str)
        and re.fullmatch(r"android-[1-9][0-9]*", platform) is not None,
        f"Android AAR manifest platform is invalid: {platform!r}",
    )
    build_tools = android.get("build_tools")
    require(
        isinstance(build_tools, str)
        and re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-rc[1-9][0-9]*)?", build_tools)
        is not None,
        f"Android AAR manifest build-tools version is invalid: {build_tools!r}",
    )
    if require_release:
        require(
            ndk == "29.0.14206865",
            "release Android AAR manifest must use NDK 29.0.14206865",
        )
        require(
            platform == "android-35",
            "release Android AAR manifest must target android-35",
        )
        require(
            build_tools == "36.0.0",
            "release Android AAR manifest must use build-tools 36.0.0",
        )

    artifacts = exact_object(
        manifest.get("artifacts"),
        MANIFEST_ARTIFACT_FIELDS,
        "Android AAR manifest artifact",
    )
    require(
        artifacts.get("aar_sha256") == aar_sha256,
        "Android AAR manifest does not bind the selected AAR bytes",
    )
    require(
        artifacts.get("classes_jar_sha256") == sha256_bytes(entries["classes.jar"]),
        "Android AAR manifest classes.jar hash mismatch",
    )
    source_hashes = {
        "script_sha256": source_root / "artifact/android-aar.sh",
        "elf_verifier_sha256": source_root / "artifact/android_elf.py",
        "release_binary_scan_sha256": source_root / "artifact/release_binary_scan.py",
        "third_party_license_collector_sha256": source_root / "artifact/third_party_licenses.py",
        "java_facade_sha256": source_root / "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
        "jni_adapter_sha256": source_root / "bindings/android/jni/qperiapt_jni.c",
    }
    for key, source_path in source_hashes.items():
        source_snapshot = read_snapshot(source_path, maximum=16 * 1024 * 1024, label=f"Android source input {key}")
        require(artifacts.get(key) == source_snapshot.sha256, f"Android AAR manifest source hash mismatch for {key}")
    contract_path = source_root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
    contract_snapshot = read_snapshot(contract_path, maximum=16 * 1024 * 1024, label="Android ABI2 contract")
    require(abi.get("contract_path") == contract_path.relative_to(source_root).as_posix(), "Android AAR manifest contract path mismatch")
    require(abi.get("contract_sha256") == contract_snapshot.sha256, "Android AAR manifest contract hash mismatch")
    native = artifacts.get("native")
    require(isinstance(native, dict) and set(native) == set(REQUIRED_ABIS), "Android AAR manifest native ABI set mismatch")
    for abi_name in REQUIRED_ABIS:
        hashes = exact_object(
            native.get(abi_name),
            MANIFEST_NATIVE_HASH_FIELDS,
            f"Android AAR manifest native hashes for {abi_name}",
        )
        require(
            hashes.get("ffi_so_sha256") == sha256_bytes(entries[f"jni/{abi_name}/{FFI_LIBRARY}"]),
            f"Android AAR manifest FFI hash mismatch for {abi_name}",
        )
        require(
            hashes.get("jni_so_sha256") == sha256_bytes(entries[f"jni/{abi_name}/{JNI_LIBRARY}"]),
            f"Android AAR manifest JNI hash mismatch for {abi_name}",
        )


def verify_aar(
    path: pathlib.Path,
    *,
    llvm_nm: pathlib.Path,
    llvm_readelf: pathlib.Path,
    manifest: pathlib.Path | None = None,
    expected_aar_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    require_release_manifest: bool = False,
    forbidden_text: Iterable[str] = (),
    extract_to: pathlib.Path | None = None,
    source_root: pathlib.Path | None = None,
) -> None:
    snapshot = read_snapshot(path, maximum=MAX_ARCHIVE_BYTES, label="Android AAR")
    if expected_aar_sha256 is not None:
        require(re.fullmatch(r"[0-9a-f]{64}", expected_aar_sha256) is not None, "invalid expected AAR SHA-256")
        require(
            hmac.compare_digest(snapshot.sha256, expected_aar_sha256),
            f"Android AAR SHA-256 mismatch: {path}",
        )
    require(manifest is not None or expected_manifest_sha256 is None, "expected manifest SHA-256 requires --manifest")
    require(not require_release_manifest or manifest is not None, "release-manifest verification requires --manifest")
    entries, class_entries = audit_aar_bytes(snapshot.data, label=str(snapshot.path))
    with tempfile.TemporaryDirectory(prefix="qperiapt-android-elf-") as temp:
        temp_root = pathlib.Path(temp)
        selected_aar = temp_root / "selected.aar"
        try:
            selected_aar.write_bytes(snapshot.data)
        except OSError as exc:
            raise AndroidVerificationError(f"cannot materialize Android AAR snapshot for scanning: {exc}") from exc
        materialized: list[pathlib.Path] = [selected_aar]
        for name, data in entries.items():
            extracted_entry = temp_root / "aar" / pathlib.PurePosixPath(name)
            extracted_entry.parent.mkdir(parents=True, exist_ok=True)
            try:
                extracted_entry.write_bytes(data)
            except OSError as exc:
                raise AndroidVerificationError(f"cannot materialize AAR entry {name} for scanning: {exc}") from exc
            materialized.append(extracted_entry)
        for name, data in class_entries.items():
            extracted_class = temp_root / "classes" / pathlib.PurePosixPath(name)
            extracted_class.parent.mkdir(parents=True, exist_ok=True)
            try:
                extracted_class.write_bytes(data)
            except OSError as exc:
                raise AndroidVerificationError(f"cannot materialize classes.jar entry {name} for scanning: {exc}") from exc
            materialized.append(extracted_class)
        scan_release_paths(materialized, forbidden_text=forbidden_text)
        for abi in REQUIRED_ABIS:
            for library in (FFI_LIBRARY, JNI_LIBRARY):
                extracted = temp_root / "aar" / "jni" / abi / library
                verify_library(
                    extracted,
                    abi=abi,
                    library=library,
                    llvm_nm=llvm_nm,
                    llvm_readelf=llvm_readelf,
                )
    if manifest is not None:
        if source_root is None:
            raise AndroidVerificationError("manifest verification requires --source-root")
        verify_manifest(
            manifest,
            aar_path=path,
            entries=entries,
            aar_sha256=snapshot.sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            require_release=require_release_manifest,
            forbidden_text=forbidden_text,
            source_root=source_root,
        )
    if extract_to is not None:
        extract_verified_entries(entries, extract_to)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    ndk = subparsers.add_parser("verify-ndk", help="require Android NDK r29 and print its revision")
    ndk.add_argument("--ndk", required=True, type=pathlib.Path)

    expected_commit = subparsers.add_parser(
        "verify-expected-commit",
        help="bind an optional release-workflow commit to the actual Android source commit",
    )
    expected_commit.add_argument("--expected", required=True)
    expected_commit.add_argument("--actual", required=True)

    toolchain = subparsers.add_parser("find-toolchain", help="print the unique usable Android NDK r29 toolchain")
    toolchain.add_argument("--ndk", required=True, type=pathlib.Path)

    tree = subparsers.add_parser("verify-tree", help="verify staged Android native libraries")
    tree.add_argument("--root", required=True, type=pathlib.Path)
    tree.add_argument("--llvm-nm", required=True, type=pathlib.Path)
    tree.add_argument("--llvm-readelf", required=True, type=pathlib.Path)

    aar = subparsers.add_parser("verify-aar", help="audit an AAR and reverify its extracted ELF files")
    aar.add_argument("--aar", required=True, type=pathlib.Path)
    aar.add_argument("--llvm-nm", required=True, type=pathlib.Path)
    aar.add_argument("--llvm-readelf", required=True, type=pathlib.Path)
    aar.add_argument("--manifest", type=pathlib.Path)
    aar.add_argument("--expected-aar-sha256")
    aar.add_argument("--expected-manifest-sha256")
    aar.add_argument("--require-release-manifest", action="store_true")
    aar.add_argument("--forbid-text", action="append", default=[])
    aar.add_argument("--extract-to", type=pathlib.Path)
    aar.add_argument("--source-root", type=pathlib.Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify-ndk":
            print(verify_ndk_r29(args.ndk))
        elif args.command == "verify-expected-commit":
            verify_expected_git_commit(args.expected, args.actual)
            print("ANDROID_EXPECTED_GIT_COMMIT_PASS")
        elif args.command == "find-toolchain":
            print(find_ndk_toolchain(args.ndk))
        elif args.command == "verify-tree":
            verify_native_tree(args.root, llvm_nm=args.llvm_nm, llvm_readelf=args.llvm_readelf)
            print("ANDROID_ELF_TREE_VERIFY_PASS")
        else:
            verify_aar(
                args.aar,
                llvm_nm=args.llvm_nm,
                llvm_readelf=args.llvm_readelf,
                manifest=args.manifest,
                expected_aar_sha256=args.expected_aar_sha256,
                expected_manifest_sha256=args.expected_manifest_sha256,
                require_release_manifest=args.require_release_manifest,
                forbidden_text=args.forbid_text,
                extract_to=args.extract_to,
                source_root=args.source_root,
            )
            print("ANDROID_AAR_ELF_VERIFY_PASS")
    except AndroidVerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
