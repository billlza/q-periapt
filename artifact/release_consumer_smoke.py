#!/usr/bin/env python3
"""Consume a semantic-verified local Q-Periapt ABI 2 release index.

This is the local analogue of an isolated downstream download, verify, unpack,
compile, and run check.  Diagnostic indexes are rejected unless the caller
explicitly opts in.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import errno
import json
import os
import pathlib
import platform
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any

from claim_ledger import canonical_tree_digest, repository_paths
from evidence_io import (
    EvidenceIOError,
    JsonObjectSnapshot,
    consume_regular_snapshot,
    load_json_object_snapshot,
)
from proof_manifest import (
    ProofManifestError,
    load_results_manifest_snapshot,
    resolve_bound_file_declaration,
)

from release_index import (
    REPOSITORY_ROOT,
    MAX_TAR_ARCHIVE_BYTES,
    SCHEMA_VERSION as RELEASE_INDEX_SCHEMA_VERSION,
    ensure_private_directory,
    normalized_absolute,
    protect_private_directory,
    require,
    require_no_symlink_components,
    release_pointer_selection,
    require_strictly_under,
    require_under,
    require_relative_safe,
    require_utc_timestamp,
    verify_index_file as verify_release_file,
    verify_release_index_snapshot,
    verify_sha256s,
)


MAX_TAR_MEMBERS = 8192
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
CONSUMER_RECEIPT_SCHEMA_VERSION = 1
CONSUMER_RECEIPT_KIND = "qperiapt.local_release_consumer_receipt"
CONSUMER_RECEIPT_LEAF = "qperiapt-release-consumer-receipt.json"
MAX_CONSUMER_RECEIPT_BYTES = 64 * 1024
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONSUMER_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "run_id",
        "generated_at",
        "status",
        "source_commit",
        "source_tree_dirty",
        "proof_source_tree_sha256",
        "index_path",
        "index_sha256",
        "index_generated_at",
        "index_schema",
        "c_archive_path",
        "c_archive_bytes",
        "c_archive_sha256",
        "android_aar_sha256",
        "android_runtime_run_id",
        "android_runtime_proof_sha256",
        "consumer_modes",
    }
)
TRUSTED_TOOL_CANDIDATES = {
    "cc": ((pathlib.Path("/usr/bin/cc"), pathlib.Path("/usr")),),
    "pkg-config": (
        (pathlib.Path("/usr/bin/pkg-config"), pathlib.Path("/usr")),
        (pathlib.Path("/opt/homebrew/bin/pkg-config"), pathlib.Path("/opt/homebrew")),
        (pathlib.Path("/usr/local/bin/pkg-config"), pathlib.Path("/usr/local")),
    ),
}


@dataclass(frozen=True, slots=True)
class VerifiedArchiveReference:
    path: pathlib.Path
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ConsumerModeResults:
    """Successful modes returned only after both consumers have executed."""

    dynamic: str
    static: str

    @classmethod
    def passed(cls) -> "ConsumerModeResults":
        return cls(dynamic="pass", static="pass")

    def receipt_value(self) -> dict[str, str]:
        require(
            self.dynamic == "pass" and self.static == "pass",
            "local release consumer modes are not both passing",
        )
        return {"dynamic": self.dynamic, "static": self.static}


def canonical_utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def android_runtime_summary_identity(
    index: dict[str, Any],
) -> tuple[str | None, str | None]:
    summaries = index.get("proof_summaries")
    require(isinstance(summaries, dict), "release index proof summaries are malformed")
    summary = summaries.get("android_runtime")
    if summary is None:
        return None, None
    require(isinstance(summary, dict), "Android runtime summary is malformed")
    result = summary.get("result")
    run_id = result.get("run_id") if isinstance(result, dict) else None
    proof_sha256 = summary.get("sha256")
    require(
        isinstance(run_id, str)
        and RUN_ID_RE.fullmatch(run_id) is not None
        and isinstance(proof_sha256, str)
        and SHA256_RE.fullmatch(proof_sha256) is not None,
        "Android runtime summary identity is malformed",
    )
    return run_id, proof_sha256


def indexed_android_aar_sha256(index: dict[str, Any]) -> str:
    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list), "release index artifacts are malformed")
    selected: list[str] = []
    for artifact in artifacts:
        require(isinstance(artifact, dict), "release artifact entry is malformed")
        if artifact.get("face") != "android":
            continue
        files = artifact.get("files")
        require(
            isinstance(files, list) and len(files) == 1,
            "Android release artifact must declare exactly one AAR",
        )
        record = files[0]
        digest = record.get("sha256") if isinstance(record, dict) else None
        require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            "Android release artifact digest is malformed",
        )
        selected.append(digest)
    require(len(selected) == 1, "release index must contain exactly one Android AAR")
    return selected[0]


def validate_consumer_receipt(
    receipt: dict[str, Any],
    *,
    root: pathlib.Path,
    expected_run_id: str,
    expected_source_commit: str,
    expected_source_tree_dirty: bool,
    expected_source_tree_sha256: str,
    expected_index_path: str,
    expected_index_sha256: str,
    expected_index_generated_at: str,
    expected_c_archive: VerifiedArchiveReference,
    expected_android_aar_sha256: str,
    expected_android_runtime_run_id: str | None,
    expected_android_runtime_proof_sha256: str | None,
) -> None:
    require(
        isinstance(receipt, dict) and set(receipt) == CONSUMER_RECEIPT_FIELDS,
        "local release consumer receipt fields differ",
    )
    require(
        type(receipt.get("schema_version")) is int
        and receipt["schema_version"] == CONSUMER_RECEIPT_SCHEMA_VERSION,
        "local release consumer receipt schema differs",
    )
    require(
        receipt.get("kind") == CONSUMER_RECEIPT_KIND,
        "local release consumer receipt kind differs",
    )
    require(
        receipt.get("run_id") == expected_run_id
        and RUN_ID_RE.fullmatch(expected_run_id) is not None,
        "local release consumer receipt run id differs",
    )
    require_utc_timestamp(
        receipt.get("generated_at"), "local release consumer receipt generated_at"
    )
    require(
        receipt.get("status") == "pass",
        "local release consumer receipt status is not pass",
    )
    require(
        isinstance(expected_source_commit, str)
        and re.fullmatch(r"[0-9a-f]{40,64}", expected_source_commit) is not None
        and type(expected_source_tree_dirty) is bool
        and isinstance(expected_source_tree_sha256, str)
        and SHA256_RE.fullmatch(expected_source_tree_sha256) is not None
        and receipt.get("source_commit") == expected_source_commit
        and receipt.get("source_tree_dirty") is expected_source_tree_dirty
        and receipt.get("proof_source_tree_sha256")
        == expected_source_tree_sha256,
        "local release consumer receipt source identity differs",
    )
    require(
        isinstance(expected_index_path, str)
        and pathlib.PurePosixPath(expected_index_path).as_posix()
        == expected_index_path
        and not pathlib.PurePosixPath(expected_index_path).is_absolute()
        and ".." not in pathlib.PurePosixPath(expected_index_path).parts
        and isinstance(expected_index_sha256, str)
        and SHA256_RE.fullmatch(expected_index_sha256) is not None
        and receipt.get("index_path") == expected_index_path
        and receipt.get("index_sha256") == expected_index_sha256
        and receipt.get("index_generated_at") == expected_index_generated_at
        and type(receipt.get("index_schema")) is int
        and receipt.get("index_schema") == RELEASE_INDEX_SCHEMA_VERSION,
        "local release consumer receipt index identity differs",
    )
    try:
        expected_archive_path = expected_c_archive.path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SystemExit(
            "error: expected local release consumer C archive escapes the repository"
        ) from exc
    require(
        receipt.get("c_archive_path") == expected_archive_path
        and type(receipt.get("c_archive_bytes")) is int
        and receipt.get("c_archive_bytes") == expected_c_archive.size
        and receipt.get("c_archive_sha256") == expected_c_archive.sha256,
        "local release consumer receipt C archive identity differs",
    )
    require(
        isinstance(expected_android_aar_sha256, str)
        and SHA256_RE.fullmatch(expected_android_aar_sha256) is not None
        and receipt.get("android_aar_sha256") == expected_android_aar_sha256,
        "local release consumer receipt Android AAR identity differs",
    )
    runtime_identity_is_valid = (
        expected_android_runtime_run_id is None
        and expected_android_runtime_proof_sha256 is None
    ) or (
        isinstance(expected_android_runtime_run_id, str)
        and RUN_ID_RE.fullmatch(expected_android_runtime_run_id) is not None
        and isinstance(expected_android_runtime_proof_sha256, str)
        and SHA256_RE.fullmatch(expected_android_runtime_proof_sha256) is not None
    )
    require(
        runtime_identity_is_valid
        and receipt.get("android_runtime_run_id") == expected_android_runtime_run_id
        and receipt.get("android_runtime_proof_sha256")
        == expected_android_runtime_proof_sha256,
        "local release consumer receipt Android runtime identity differs",
    )
    require(
        receipt.get("consumer_modes") == {"dynamic": "pass", "static": "pass"},
        "local release consumer receipt mode results differ",
    )


def c_archive_entries(
    index: dict[str, Any], release_root: pathlib.Path
) -> list[VerifiedArchiveReference]:
    entries: list[VerifiedArchiveReference] = []
    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list), "release index artifacts are malformed")
    for artifact in artifacts:
        require(isinstance(artifact, dict), "release artifact entry is malformed")
        if artifact.get("face") != "c-abi":
            continue
        require(artifact.get("type") == "tar.gz", "C ABI artifact type must be tar.gz")
        files = artifact.get("files")
        require(isinstance(files, list) and files, "C ABI artifact lacks files")
        for item in files:
            path = verify_release_file(release_root, item)
            require(path.name.endswith(".tar.gz"), f"C ABI package is not a tar.gz: {path}")
            require(isinstance(item, dict), "C ABI package entry is malformed")
            size = item.get("bytes")
            digest = item.get("sha256")
            require(type(size) is int, "C ABI package size is malformed")
            require(isinstance(digest, str), "C ABI package digest is malformed")
            entries.append(
                VerifiedArchiveReference(path=path, size=size, sha256=digest)
            )
    require(len(entries) == 1, f"release index must have exactly one C ABI archive, found {len(entries)}")
    return entries


def safe_extract_tar_gz(
    archive: VerifiedArchiveReference, dest: pathlib.Path
) -> None:
    require(not dest.is_symlink(), f"tar destination must not be a symlink: {dest}")
    try:
        dest.mkdir(parents=True, mode=0o700, exist_ok=True)
        protect_private_directory(dest, "release consumer extraction")
        with tempfile.SpooledTemporaryFile(
            max_size=8 * 1024 * 1024,
            mode="w+b",
        ) as captured:
            def write_archive(chunk: bytes) -> None:
                written = captured.write(chunk)
                require(written == len(chunk), "short write while capturing C archive")

            snapshot = consume_regular_snapshot(
                archive.path,
                maximum=MAX_TAR_ARCHIVE_BYTES,
                label="indexed C archive",
                consume=write_archive,
            )
            require(
                snapshot.size == archive.size and snapshot.sha256 == archive.sha256,
                "indexed C archive changed after release-index verification",
            )
            captured.flush()
            captured.seek(0)
            with tarfile.open(fileobj=captured, mode="r:gz") as bundle:
                member_count = 0
                seen: set[str] = set()
                total_size = 0
                for member in bundle:
                    member_count += 1
                    require(
                        member_count <= MAX_TAR_MEMBERS,
                        f"archive has too many members: {archive.path}",
                    )
                    name = member.name
                    pure = pathlib.PurePosixPath(name)
                    require(
                        name and not pure.is_absolute(),
                        f"absolute/empty tar member: {name}",
                    )
                    accepted_name = (
                        name[:-1]
                        if member.isdir() and name.endswith("/")
                        else name
                    )
                    canonical = require_relative_safe(
                        pure.as_posix(), "consumer tar member"
                    )
                    require(
                        accepted_name == canonical,
                        f"non-canonical tar member: {name}",
                    )
                    require(
                        canonical not in seen,
                        f"duplicate tar member: {canonical}",
                    )
                    seen.add(canonical)
                    require(
                        member.isfile() or member.isdir(),
                        f"unsupported tar member type: {name}",
                    )
                    if member.isfile():
                        require(member.size >= 0, f"negative tar member size: {name}")
                        total_size += member.size
                        require(
                            total_size <= MAX_EXTRACTED_BYTES,
                            f"archive exceeds extracted-size limit: {archive.path}",
                        )
                    safe_member = copy.copy(member)
                    safe_member.name = canonical
                    target = dest / pathlib.Path(canonical)
                    require_under(target, dest, "tar extraction target")
                    bundle.extract(safe_member, dest, filter="data")
                require(member_count > 0, f"archive is empty: {archive.path}")
    except (EvidenceIOError, OSError, tarfile.TarError) as exc:
        raise SystemExit(f"error: cannot extract {archive.path}: {exc}") from exc


def find_c_package_root(extract_root: pathlib.Path) -> pathlib.Path:
    candidates = []
    for path in extract_root.rglob("lib/pkgconfig/qperiapt-abi2.pc"):
        require_no_symlink_components(path, extract_root, "C package pkg-config file")
        package_root = path.parents[2]
        if (
            (package_root / "share/q-periapt/smoke.c").is_file()
            and (package_root / "SHA256SUMS").is_file()
            and (package_root / "MANIFEST.json").is_file()
        ):
            candidates.append(package_root)
    require(len(candidates) == 1, f"expected exactly one C package root, found {len(candidates)}")
    return candidates[0]


def need_tool(name: str) -> str:
    candidates = TRUSTED_TOOL_CANDIDATES.get(name)
    require(candidates is not None, f"unsupported required tool: {name}")
    for candidate, trusted_root in candidates:
        if not os.path.lexists(candidate):
            continue
        try:
            resolved = candidate.resolve(strict=True)
            resolved_metadata = resolved.lstat()
            resolved_trusted_root = trusted_root.resolve(strict=True)
        except OSError as exc:
            raise SystemExit(
                f"error: cannot authenticate required tool {name}: {exc}"
            ) from exc
        require(
            resolved.is_relative_to(resolved_trusted_root),
            f"required tool resolves outside its trusted installation root: {resolved}",
        )
        require(
            stat.S_ISREG(resolved_metadata.st_mode),
            f"required tool is not a regular file: {resolved}",
        )
        require(
            os.access(resolved, os.X_OK),
            f"required tool is not executable: {resolved}",
        )
        return str(resolved)
    raise SystemExit(f"error: required trusted tool not found: {name}")


def tool_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LANG": "C",
    }


def run_cmd(
    args: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None
) -> str:
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.returncode != 0:
        raise SystemExit(f"error: command failed ({proc.returncode}): {' '.join(args)}")
    return proc.stdout


def _normalized_flag_path(raw: str, package_root: pathlib.Path, label: str) -> pathlib.Path:
    path = pathlib.Path(raw)
    require(path.is_absolute(), f"{label} path must be absolute: {raw}")
    normalized = normalized_absolute(path)
    require_under(normalized, package_root, label)
    require_no_symlink_components(normalized, package_root, label)
    return normalized


def validate_pkg_config_flags(
    package_root: pathlib.Path,
    flags: list[str],
    *,
    static: bool,
) -> list[str]:
    include_dir = normalized_absolute(package_root / "include/qperiapt/abi2")
    library_dir = normalized_absolute(package_root / "lib")
    expected_library_names = (
        {"libq_periapt_ffi_abi2.a"}
        if static
        else {"libq_periapt_ffi.so.2", "libq_periapt_ffi.2.dylib"}
    )
    allowed_system_libraries = {
        "-ldl",
        "-lgcc_s",
        "-liconv",
        "-lc",
        "-lm",
        "-lpthread",
        "-lrt",
        "-lutil",
    }
    saw_include = False
    saw_library = False
    saw_rpath = False
    validated: list[str] = []
    for flag in flags:
        require(flag and "\x00" not in flag and "\n" not in flag and "\r" not in flag, "pkg-config emitted a malformed flag")
        if flag.startswith("-I"):
            require(not saw_include, "pkg-config emitted duplicate include flags")
            path = _normalized_flag_path(flag[2:], package_root, "pkg-config include")
            require(path == include_dir, f"pkg-config include path differs: {path}")
            validated.append(f"-I{path}")
            saw_include = True
            continue
        if flag.startswith("-Wl,-rpath,"):
            require(not static, "static pkg-config flags must not contain rpath")
            require(not saw_rpath, "pkg-config emitted duplicate rpath flags")
            path = _normalized_flag_path(
                flag.removeprefix("-Wl,-rpath,"), package_root, "pkg-config rpath"
            )
            require(path == library_dir, f"pkg-config rpath differs: {path}")
            validated.append(f"-Wl,-rpath,{path}")
            saw_rpath = True
            continue
        if flag in allowed_system_libraries:
            require(static, f"dynamic pkg-config flags contain unexpected system library: {flag}")
            validated.append(flag)
            continue
        path = _normalized_flag_path(flag, package_root, "pkg-config library")
        require(not saw_library, "pkg-config emitted duplicate package libraries")
        require(path.parent == library_dir, f"pkg-config library escapes package lib directory: {path}")
        require(path.name in expected_library_names, f"pkg-config library name is unsupported: {path.name}")
        require(path.is_file() and not path.is_symlink(), f"pkg-config library is not a regular file: {path}")
        validated.append(str(path))
        saw_library = True
    require(saw_include, "pkg-config did not emit the canonical include directory")
    require(saw_library, "pkg-config did not emit the canonical package library")
    require(saw_rpath is not static, "pkg-config rpath presence differs from linkage mode")
    return validated


def pkg_config(
    package_root: pathlib.Path,
    package: str,
    static: bool,
    pkg_config_tool: str,
) -> list[str]:
    env = tool_environment()
    env["PKG_CONFIG_PATH"] = str(package_root / "lib/pkgconfig")
    env["PKG_CONFIG_LIBDIR"] = env["PKG_CONFIG_PATH"]
    env["PKG_CONFIG_SYSTEM_INCLUDE_PATH"] = ""
    env["PKG_CONFIG_SYSTEM_LIBRARY_PATH"] = ""
    args = [pkg_config_tool, "--cflags", "--libs"]
    if static:
        args.append("--static")
    args.append(package)
    return validate_pkg_config_flags(
        package_root,
        shlex.split(run_cmd(args, cwd=package_root, env=env)),
        static=static,
    )


def runtime_env(package_root: pathlib.Path) -> dict[str, str]:
    env = tool_environment()
    lib_dir = str(package_root / "lib")
    for key in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        old = env.get(key)
        env[key] = lib_dir if not old else f"{lib_dir}{os.pathsep}{old}"
    return env


def compile_and_run_c_smoke(
    package_root: pathlib.Path,
    work: pathlib.Path,
    cc: str,
    label: str,
    flags: list[str],
) -> None:
    out = work / f"qperiapt_c_{label}_smoke"
    cmd = [
        cc,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "share/q-periapt/smoke.c",
        *flags,
        "-o",
        str(out),
    ]
    run_cmd(cmd, cwd=package_root, env=tool_environment())
    output = run_cmd([str(out)], cwd=package_root, env=runtime_env(package_root))
    require("ALL PASS" in output, f"C {label} smoke did not print ALL PASS")


def smoke_c_archive(
    root: pathlib.Path,
    index_sha256: str,
    archive: VerifiedArchiveReference,
    out_dir: pathlib.Path,
) -> ConsumerModeResults:
    work = (
        out_dir
        / index_sha256[:16]
        / archive.path.name.removesuffix(".tar.gz")
    )
    require_strictly_under(work, out_dir, "release consumer work directory")
    require_no_symlink_components(work, out_dir, "release consumer work directory")
    try:
        if work.exists():
            require(work.is_dir(), f"release consumer work path is not a directory: {work}")
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise SystemExit(
            f"error: cannot recreate release consumer work directory {work}: {exc}"
        ) from exc
    safe_extract_tar_gz(archive, work / "extract")
    package_root = find_c_package_root(work / "extract")
    verify_sha256s(package_root)
    cc = need_tool("cc")
    pkg_config_tool = need_tool("pkg-config")
    system = platform.system()
    require(system in {"Darwin", "Linux"}, f"C consumer supports Darwin/Linux, got {system}")
    compile_and_run_c_smoke(
        package_root,
        work,
        cc,
        "dynamic",
        pkg_config(
            package_root,
            "qperiapt-abi2",
            static=False,
            pkg_config_tool=pkg_config_tool,
        ),
    )
    compile_and_run_c_smoke(
        package_root,
        work,
        cc,
        "static",
        pkg_config(
            package_root,
            "qperiapt-abi2-static",
            static=True,
            pkg_config_tool=pkg_config_tool,
        ),
    )
    require_under(work, root / "target", "release consumer smoke output")
    return ConsumerModeResults.passed()


def resolve_output_dir() -> pathlib.Path:
    root = REPOSITORY_ROOT
    target = root / "target"
    output = target / "qperiapt-release-consumer-smoke"
    require_no_symlink_components(output, target, "release consumer output")
    if output.exists():
        require(output.is_dir(), f"release consumer output is not a directory: {output}")
    else:
        try:
            output.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise SystemExit(
                f"error: cannot create release consumer output {output}: {exc}"
            ) from exc
    protect_private_directory(output, "release consumer output")
    return output


def _open_private_directory(path: pathlib.Path, label: str) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise SystemExit(f"error: cannot open {label} {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"{label} must be one current-user private directory",
        )
    except BaseException as primary:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            _raise_visible_cleanup_failure(
                primary,
                f"closing rejected {label} also failed: {cleanup_error}",
            )
        raise
    return descriptor


def _close_descriptor(descriptor: int, label: str, primary: BaseException | None) -> None:
    try:
        os.close(descriptor)
    except BaseException as cleanup_error:
        if primary is not None:
            _raise_visible_cleanup_failure(
                primary,
                f"closing {label} also failed: {cleanup_error}",
            )
        elif isinstance(cleanup_error, Exception):
            raise SystemExit(f"error: cannot close {label}: {cleanup_error}") from cleanup_error
        else:
            raise


def _raise_visible_cleanup_failure(
    primary: BaseException, detail: str
) -> None:
    """Preserve non-SystemExit notes and make CLI SystemExit cleanup failures visible."""

    if isinstance(primary, SystemExit):
        message = str(primary.code) if primary.code not in {None, ""} else "error"
        raise SystemExit(f"{message}; cleanup also failed: {detail}") from primary
    primary.add_note(detail)


def _fsync_private_directory(path: pathlib.Path, label: str) -> None:
    descriptor = _open_private_directory(path, label)
    primary: BaseException | None = None
    try:
        os.fsync(descriptor)
    except OSError as exc:
        primary = SystemExit(f"error: cannot persist {label} {path}: {exc}")
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_descriptor(descriptor, label, primary)


def _private_receipt_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "local release consumer receipt must be one current-user-owned "
            "regular file with mode 0600"
        )


def load_private_consumer_receipt(
    path: pathlib.Path, *, expected_sha256: str | None = None
) -> JsonObjectSnapshot:
    try:
        snapshot = load_json_object_snapshot(
            path,
            maximum=MAX_CONSUMER_RECEIPT_BYTES,
            label="local release consumer receipt",
            validate_metadata=_private_receipt_metadata,
        )
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc
    if expected_sha256 is not None:
        require(
            isinstance(expected_sha256, str)
            and SHA256_RE.fullmatch(expected_sha256) is not None,
            "expected local release consumer receipt digest is malformed",
        )
        require(
            snapshot.file.sha256 == expected_sha256,
            "local release consumer receipt hash differs from results manifest",
        )
    return snapshot


def _publish_append_only_receipt(run_directory: pathlib.Path, data: bytes) -> None:
    """Atomically link one complete private receipt without replacing a leaf."""

    require(
        type(data) is bytes and 0 < len(data) <= MAX_CONSUMER_RECEIPT_BYTES,
        "local release consumer receipt bytes are empty or oversized",
    )
    directory_fd = _open_private_directory(
        run_directory, "release consumer receipt run"
    )
    pending_leaf = f".{CONSUMER_RECEIPT_LEAF}.pending-{secrets.token_hex(16)}"
    pending_fd = -1
    pending_visible = False
    primary: BaseException | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        pending_fd = os.open(pending_leaf, flags, 0o600, dir_fd=directory_fd)
        pending_visible = True
        os.fchmod(pending_fd, 0o600)
        _private_receipt_metadata(os.fstat(pending_fd))
        remaining = memoryview(data)
        while remaining:
            written = os.write(pending_fd, remaining)
            require(written > 0, "short write for local release consumer receipt")
            remaining = remaining[written:]
        os.fsync(pending_fd)
        completed_fd = pending_fd
        pending_fd = -1
        os.close(completed_fd)
        try:
            os.link(
                pending_leaf,
                CONSUMER_RECEIPT_LEAF,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise SystemExit(
                    "error: local release consumer receipt is append-only and already exists"
                ) from exc
            raise
        os.unlink(pending_leaf, dir_fd=directory_fd)
        pending_visible = False
        os.fsync(directory_fd)
    except OSError as exc:
        primary = SystemExit(
            f"error: cannot publish append-only local release consumer receipt: {exc}"
        )
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if pending_fd >= 0:
            try:
                os.close(pending_fd)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if pending_visible:
            try:
                os.unlink(pending_leaf, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        try:
            os.close(directory_fd)
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            if primary is not None:
                detail = "; ".join(
                    "local release consumer receipt staging cleanup also failed: "
                    f"{cleanup_error}"
                    for cleanup_error in cleanup_errors
                )
                _raise_visible_cleanup_failure(primary, detail)
            else:
                raise SystemExit(
                    "error: local release consumer receipt staging cleanup failed: "
                    f"{cleanup_errors[0]}"
                ) from cleanup_errors[0]


def publish_consumer_receipt(
    *,
    root: pathlib.Path,
    out_dir: pathlib.Path,
    index_path: pathlib.Path,
    index_sha256: str,
    index: dict[str, Any],
    archive: VerifiedArchiveReference,
    mode_results: ConsumerModeResults,
) -> JsonObjectSnapshot:
    """Publish one append-only receipt only after both C consumers pass."""

    source = index.get("git")
    require(isinstance(source, dict), "release index Git provenance is malformed")
    source_commit = source.get("commit")
    source_dirty = source.get("source_tree_dirty")
    require(
        isinstance(source_commit, str)
        and re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is not None
        and type(source_dirty) is bool,
        "release index Git provenance is malformed",
    )
    require(
        index.get("channel") == "release"
        and index.get("diagnostic_only") is False
        and source_dirty is False,
        "local release consumer receipts require a clean release-channel index",
    )
    require(
        type(index.get("schema_version")) is int
        and index.get("schema_version") == RELEASE_INDEX_SCHEMA_VERSION,
        "release index schema differs before consumer receipt publication",
    )
    index_generated_at = require_utc_timestamp(
        index.get("generated_at"), "release index generated_at"
    )
    require(
        isinstance(index_sha256, str) and SHA256_RE.fullmatch(index_sha256) is not None,
        "release index digest is malformed before consumer receipt publication",
    )
    try:
        index_relative = index_path.relative_to(root).as_posix()
        archive_relative = archive.path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SystemExit(
            "error: local release consumer inputs must remain under the repository"
        ) from exc
    run_id = secrets.token_hex(16)
    require(
        RUN_ID_RE.fullmatch(run_id) is not None,
        "generated local release consumer receipt run id is malformed",
    )
    generated_at = canonical_utc_now()
    runtime_run_id, runtime_sha256 = android_runtime_summary_identity(index)
    source_tree_sha256 = canonical_tree_digest(root, repository_paths(root))
    android_aar_sha256 = indexed_android_aar_sha256(index)
    receipt = {
        "schema_version": CONSUMER_RECEIPT_SCHEMA_VERSION,
        "kind": CONSUMER_RECEIPT_KIND,
        "run_id": run_id,
        "generated_at": generated_at,
        "status": "pass",
        "source_commit": source_commit,
        "source_tree_dirty": source_dirty,
        "proof_source_tree_sha256": source_tree_sha256,
        "index_path": index_relative,
        "index_sha256": index_sha256,
        "index_generated_at": index_generated_at,
        "index_schema": index["schema_version"],
        "c_archive_path": archive_relative,
        "c_archive_bytes": archive.size,
        "c_archive_sha256": archive.sha256,
        "android_aar_sha256": android_aar_sha256,
        "android_runtime_run_id": runtime_run_id,
        "android_runtime_proof_sha256": runtime_sha256,
        "consumer_modes": mode_results.receipt_value(),
    }
    validate_consumer_receipt(
        receipt,
        root=root,
        expected_run_id=run_id,
        expected_source_commit=source_commit,
        expected_source_tree_dirty=source_dirty,
        expected_source_tree_sha256=source_tree_sha256,
        expected_index_path=index_relative,
        expected_index_sha256=index_sha256,
        expected_index_generated_at=index_generated_at,
        expected_c_archive=archive,
        expected_android_aar_sha256=android_aar_sha256,
        expected_android_runtime_run_id=runtime_run_id,
        expected_android_runtime_proof_sha256=runtime_sha256,
    )

    receipts = out_dir / "receipts"
    ensure_private_directory(receipts, out_dir)
    _fsync_private_directory(out_dir, "release consumer output")
    run_directory = receipts / run_id
    receipt_path = run_directory / CONSUMER_RECEIPT_LEAF
    run_directory_created = False
    primary: BaseException | None = None
    try:
        try:
            run_directory.mkdir(mode=0o700, exist_ok=False)
            run_directory_created = True
        except FileExistsError as exc:
            raise SystemExit(
                "error: local release consumer receipt run already exists; "
                "refusing replacement"
            ) from exc
        protect_private_directory(run_directory, "release consumer receipt run")
        _fsync_private_directory(receipts, "release consumer receipt parent")
        _publish_append_only_receipt(
            run_directory,
            (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        snapshot = load_private_consumer_receipt(receipt_path)
        validate_consumer_receipt(
            snapshot.value,
            root=root,
            expected_run_id=run_id,
            expected_source_commit=source_commit,
            expected_source_tree_dirty=source_dirty,
            expected_source_tree_sha256=source_tree_sha256,
            expected_index_path=index_relative,
            expected_index_sha256=index_sha256,
            expected_index_generated_at=index_generated_at,
            expected_c_archive=archive,
            expected_android_aar_sha256=android_aar_sha256,
            expected_android_runtime_run_id=runtime_run_id,
            expected_android_runtime_proof_sha256=runtime_sha256,
        )
        return snapshot
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if (
            primary is not None
            and run_directory_created
            and not os.path.lexists(receipt_path)
        ):
            try:
                run_directory.rmdir()
                _fsync_private_directory(receipts, "release consumer receipt parent")
            except BaseException as cleanup_error:
                _raise_visible_cleanup_failure(
                    primary,
                    "release consumer receipt cleanup also failed: "
                    f"{cleanup_error}",
                )


def run_consumer(args: argparse.Namespace) -> None:
    root = REPOSITORY_ROOT
    require(
        args.channel == "release" or args.allow_diagnostic,
        "diagnostic release consumer requires --allow-diagnostic",
    )
    out_dir = resolve_output_dir()
    selection = release_pointer_selection(root, args.channel)
    verified_index = verify_release_index_snapshot(
        selection.path,
        root,
        allow_diagnostic=args.allow_diagnostic,
        expected_index_sha256=selection.expected_sha256,
        expected_generated_at=selection.expected_generated_at,
    )
    index = verified_index.value
    release_root = verified_index.path.parent
    archives = c_archive_entries(index, release_root)
    mode_results = smoke_c_archive(
        root, verified_index.sha256, archives[0], out_dir
    )
    verify_release_index_snapshot(
        selection.path,
        root,
        allow_diagnostic=args.allow_diagnostic,
        expected_index_sha256=selection.expected_sha256,
        expected_generated_at=selection.expected_generated_at,
    )
    if args.channel == "release":
        receipt = publish_consumer_receipt(
            root=root,
            out_dir=out_dir,
            index_path=verified_index.path,
            index_sha256=verified_index.sha256,
            index=index,
            archive=archives[0],
            mode_results=mode_results,
        )
        verify_release_index_snapshot(
            selection.path,
            root,
            allow_diagnostic=False,
            expected_index_sha256=selection.expected_sha256,
            expected_generated_at=selection.expected_generated_at,
        )
        print(
            "QPERIAPT_RELEASE_CONSUMER_RECEIPT_PASS "
            f"run-id={receipt.value['run_id']} sha256={receipt.file.sha256} "
            f"path={receipt.file.path}"
        )
        print("QPERIAPT_RELEASE_CONSUMER_SMOKE_PASS c-abi")
    else:
        print("QPERIAPT_DIAGNOSTIC_RELEASE_CONSUMER_SMOKE_PASS c-abi receipt=not_emitted")


def verify_bound_consumer(expected_results_manifest_sha256: str) -> None:
    """Verify one results-selected index and its persisted consumer receipt."""

    root = REPOSITORY_ROOT
    results_path = root / "artifact/results.json"
    try:
        manifest = load_results_manifest_snapshot(
            results_path,
            expected_sha256=expected_results_manifest_sha256,
        )
        index_declaration = resolve_bound_file_declaration(
            root, manifest, binding="local_release_index"
        )
        receipt_declaration = resolve_bound_file_declaration(
            root, manifest, binding="local_release_consumer"
        )
    except ProofManifestError as exc:
        raise SystemExit(f"error: {exc}") from exc

    section = manifest.value["local_release_index"]
    runtime = manifest.value["android_device_runtime"]
    aar = manifest.value["android_aar"]
    expected_receipt_path = (
        root
        / "target"
        / "qperiapt-release-consumer-smoke"
        / "receipts"
        / section["consumer_receipt_run_id"]
        / CONSUMER_RECEIPT_LEAF
    )
    require(
        receipt_declaration.path == expected_receipt_path,
        "results-selected local release consumer receipt path is not canonical",
    )
    for directory, label in (
        (expected_receipt_path.parents[2], "release consumer output"),
        (expected_receipt_path.parents[1], "release consumer receipt parent"),
        (expected_receipt_path.parent, "release consumer receipt run"),
    ):
        descriptor = _open_private_directory(directory, label)
        _close_descriptor(descriptor, label, None)
    receipt = load_private_consumer_receipt(
        receipt_declaration.path,
        expected_sha256=receipt_declaration.sha256,
    )
    verified_index = verify_release_index_snapshot(
        index_declaration.path,
        root,
        allow_diagnostic=False,
        expected_index_sha256=index_declaration.sha256,
        expected_generated_at=section["generated_at"],
    )
    index = verified_index.value
    runtime_run_id, runtime_sha256 = android_runtime_summary_identity(index)
    require(
        runtime_run_id == runtime["run_id"]
        and runtime_sha256 == runtime["proof_sha256"]
        and runtime_run_id == section["android_runtime_run_id"]
        and runtime_sha256 == section["android_runtime_proof_sha256"],
        "results-selected local index does not contain the selected Android runtime",
    )
    index_aar_sha256 = indexed_android_aar_sha256(index)
    require(
        index_aar_sha256 == aar["aar_sha256"],
        "results-selected local index does not contain the selected Android AAR",
    )
    archives = c_archive_entries(index, verified_index.path.parent)
    validate_consumer_receipt(
        receipt.value,
        root=root,
        expected_run_id=section["consumer_receipt_run_id"],
        expected_source_commit=section["source_commit"],
        expected_source_tree_dirty=False,
        expected_source_tree_sha256=section["proof_source_tree_sha256"],
        expected_index_path=section["index_path"],
        expected_index_sha256=section["index_sha256"],
        expected_index_generated_at=section["generated_at"],
        expected_c_archive=archives[0],
        expected_android_aar_sha256=index_aar_sha256,
        expected_android_runtime_run_id=runtime_run_id,
        expected_android_runtime_proof_sha256=runtime_sha256,
    )
    require(
        receipt.value["generated_at"] == section["consumer_receipt_generated_at"],
        "local release consumer receipt generation time differs from results",
    )
    print(
        "QPERIAPT_RESULTS_BOUND_RELEASE_CONSUMER_VERIFY_PASS "
        f"index_sha256={verified_index.sha256} receipt_sha256={receipt.file.sha256}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--channel", choices=["release", "diagnostic"], default="release")
    run.add_argument("--allow-diagnostic", action="store_true")
    verify_bound = subparsers.add_parser("verify-bound")
    verify_bound.add_argument("--expected-results-manifest-sha256", required=True)
    args = parser.parse_args()
    if args.command == "run":
        run_consumer(args)
    else:
        verify_bound_consumer(args.expected_results_manifest_sha256)


if __name__ == "__main__":
    main()
