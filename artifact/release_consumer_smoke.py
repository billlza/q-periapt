#!/usr/bin/env python3
"""Consume a semantic-verified local Q-Periapt ABI 2 release index.

This is the local analogue of an isolated downstream download, verify, unpack,
compile, and run check.  Diagnostic indexes are rejected unless the caller
explicitly opts in.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot
from release_index import (
    SCHEMA_VERSION,
    normalized_absolute,
    require,
    require_no_symlink_components,
    require_relative_safe,
    require_strictly_under,
    require_under,
    sha256_file,
    verify_index_file as verify_release_file,
    verify_release_index,
    verify_sha256s,
)


POINTER_KIND = "qperiapt.local_release_index.pointer"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_TAR_MEMBERS = 8192
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024


def load_json(path: pathlib.Path) -> dict[str, Any]:
    require(not path.is_symlink(), f"consumer JSON must not be a symlink: {path}")
    try:
        return load_json_object_snapshot(path, label=f"consumer JSON {path}").value
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc


def pointer_index_path(root: pathlib.Path, pointer_path: pathlib.Path) -> pathlib.Path:
    target = root / "target"
    release_base = target / "qperiapt-local-release"
    require_no_symlink_components(pointer_path, target, "release pointer")
    require(pointer_path.is_file(), f"release pointer missing: {pointer_path}")
    pointer = load_json(pointer_path)
    require(pointer.get("schema_version") == SCHEMA_VERSION, "release pointer schema mismatch")
    require(pointer.get("kind") == POINTER_KIND, "release pointer kind mismatch")
    require(pointer.get("channel") == "release", "default release pointer must select release channel")
    require(pointer.get("diagnostic_only") is False, "default release pointer must not be diagnostic")
    rel = pointer.get("index_path")
    expected = pointer.get("index_sha256")
    require(isinstance(rel, str), "release pointer lacks index_path")
    require(
        isinstance(expected, str) and HEX_SHA256.fullmatch(expected) is not None,
        "release pointer lacks a valid index_sha256",
    )
    require_relative_safe(rel, "release pointer index_path")
    index_path = normalized_absolute(target / pathlib.Path(rel))
    require_strictly_under(index_path, release_base / "release", "default release index")
    require_no_symlink_components(index_path, target, "default release index")
    require(index_path.is_file(), f"default release index missing: {index_path}")
    require(sha256_file(index_path) == expected, "release pointer index hash mismatch")
    return index_path


def default_index_path(root: pathlib.Path) -> pathlib.Path:
    release_base = root / "target" / "qperiapt-local-release"
    primary = release_base / "latest-release.json"
    if primary.exists() or primary.is_symlink():
        return pointer_index_path(root, primary)
    # Schema-2 release emitters also update latest.json for compatibility.  It
    # is still required to point at the release channel, never diagnostics.
    return pointer_index_path(root, release_base / "latest.json")


def resolve_index_path(root: pathlib.Path, raw: str) -> pathlib.Path:
    if not raw:
        return default_index_path(root)
    index_path = pathlib.Path(raw)
    if not index_path.is_absolute():
        index_path = root / index_path
    index_path = normalized_absolute(index_path)
    release_base = root / "target" / "qperiapt-local-release"
    require_strictly_under(index_path, release_base, "release index")
    require_no_symlink_components(index_path, root / "target", "release index")
    require(index_path.is_file(), f"release index missing: {index_path}")
    return index_path


def c_archive_entries(index: dict[str, Any], release_root: pathlib.Path) -> list[pathlib.Path]:
    entries: list[pathlib.Path] = []
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
            entries.append(path)
    require(len(entries) == 1, f"release index must have exactly one C ABI archive, found {len(entries)}")
    return entries


def safe_extract_tar_gz(archive: pathlib.Path, dest: pathlib.Path) -> None:
    require(not dest.is_symlink(), f"tar destination must not be a symlink: {dest}")
    try:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            require(members, f"archive is empty: {archive}")
            require(
                len(members) <= MAX_TAR_MEMBERS,
                f"archive has too many members: {archive}",
            )
            seen: set[str] = set()
            total_size = 0
            for member in members:
                name = member.name
                pure = pathlib.PurePosixPath(name)
                require(name and not pure.is_absolute(), f"absolute/empty tar member: {name}")
                require("\\" not in name, f"backslash tar member is unsupported: {name}")
                require(":" not in pure.parts[0], f"drive-like tar member is unsupported: {name}")
                require(
                    all(part not in {"", ".", ".."} for part in pure.parts),
                    f"unsafe tar member: {name}",
                )
                require(name not in seen, f"duplicate tar member: {name}")
                seen.add(name)
                require(member.isfile() or member.isdir(), f"unsupported tar member type: {name}")
                if member.isfile():
                    require(member.size >= 0, f"negative tar member size: {name}")
                    total_size += member.size
                    require(
                        total_size <= MAX_EXTRACTED_BYTES,
                        f"archive exceeds extracted-size limit: {archive}",
                    )
                target = dest / pathlib.Path(*pure.parts)
                require_under(target, dest, "tar extraction target")
            bundle.extractall(dest, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit(f"error: cannot extract {archive}: {exc}") from exc


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
    path = shutil.which(name)
    require(path is not None, f"required tool not found: {name}")
    return path


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


def pkg_config(package_root: pathlib.Path, package: str, static: bool) -> list[str]:
    env = os.environ.copy()
    env["PKG_CONFIG_PATH"] = str(package_root / "lib/pkgconfig")
    args = ["pkg-config", "--cflags", "--libs"]
    if static:
        args.append("--static")
    args.append(package)
    return shlex.split(run_cmd(args, cwd=package_root, env=env))


def runtime_env(package_root: pathlib.Path) -> dict[str, str]:
    env = os.environ.copy()
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
    run_cmd(cmd, cwd=package_root)
    output = run_cmd([str(out)], cwd=package_root, env=runtime_env(package_root))
    require("ALL PASS" in output, f"C {label} smoke did not print ALL PASS")


def smoke_c_archive(
    root: pathlib.Path,
    index_path: pathlib.Path,
    archive: pathlib.Path,
    out_dir: pathlib.Path,
) -> None:
    index_sha = sha256_file(index_path)
    work = out_dir / index_sha[:16] / archive.name.removesuffix(".tar.gz")
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
    need_tool("pkg-config")
    system = platform.system()
    require(system in {"Darwin", "Linux"}, f"C consumer supports Darwin/Linux, got {system}")
    compile_and_run_c_smoke(
        package_root,
        work,
        cc,
        "dynamic",
        pkg_config(package_root, "qperiapt-abi2", static=False),
    )
    compile_and_run_c_smoke(
        package_root,
        work,
        cc,
        "static",
        pkg_config(package_root, "qperiapt-abi2-static", static=True),
    )
    require_under(work, root / "target", "release consumer smoke output")


def resolve_output_dir(root: pathlib.Path, raw: str) -> pathlib.Path:
    target = root / "target"
    base = target / "qperiapt-release-consumer-smoke"
    if raw:
        value = pathlib.Path(raw)
        if not value.is_absolute():
            value = root / value
        output = normalized_absolute(value)
        require_under(output, base, "release consumer output")
    else:
        output = base
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
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--index", default=os.environ.get("QPERIAPT_RELEASE_INDEX_PATH", ""))
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--allow-diagnostic", action="store_true")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    out_dir = resolve_output_dir(root, args.out_dir)
    index_path = resolve_index_path(root, args.index)
    index = verify_release_index(
        index_path, root, allow_diagnostic=args.allow_diagnostic
    )
    release_root = index_path.parent
    for archive in c_archive_entries(index, release_root):
        smoke_c_archive(root, index_path, archive, out_dir)
    print("QPERIAPT_RELEASE_CONSUMER_SMOKE_PASS c-abi")


if __name__ == "__main__":
    main()
