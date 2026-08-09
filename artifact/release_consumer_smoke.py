#!/usr/bin/env python3
"""Consume a semantic-verified local Q-Periapt ABI 2 release index.

This is the local analogue of an isolated downstream download, verify, unpack,
compile, and run check.  Diagnostic indexes are rejected unless the caller
explicitly opts in.
"""

from __future__ import annotations

import argparse
import copy
import os
import pathlib
import platform
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any

from evidence_io import EvidenceIOError, consume_regular_snapshot

from release_index import (
    REPOSITORY_ROOT,
    MAX_TAR_ARCHIVE_BYTES,
    normalized_absolute,
    protect_private_directory,
    require,
    require_no_symlink_components,
    release_pointer_selection,
    require_strictly_under,
    require_under,
    require_relative_safe,
    verify_index_file as verify_release_file,
    verify_release_index,
    verify_sha256s,
)


MAX_TAR_MEMBERS = 8192
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
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
) -> None:
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", choices=["release", "diagnostic"], default="release")
    parser.add_argument("--allow-diagnostic", action="store_true")
    args = parser.parse_args()

    root = REPOSITORY_ROOT
    require(
        args.channel == "release" or args.allow_diagnostic,
        "diagnostic release consumer requires --allow-diagnostic",
    )
    out_dir = resolve_output_dir()
    selection = release_pointer_selection(root, args.channel)
    index = verify_release_index(
        selection.path,
        root,
        allow_diagnostic=args.allow_diagnostic,
        expected_index_sha256=selection.expected_sha256,
        expected_generated_at=selection.expected_generated_at,
    )
    release_root = selection.path.parent
    for archive in c_archive_entries(index, release_root):
        smoke_c_archive(root, selection.expected_sha256, archive, out_dir)
    print("QPERIAPT_RELEASE_CONSUMER_SMOKE_PASS c-abi")


if __name__ == "__main__":
    main()
