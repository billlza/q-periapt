#!/usr/bin/env python3
"""Consume a local Q-Periapt release index from an isolated C project.

This is the current local analogue of a downstream "download, verify, unpack,
compile, and run" check. It intentionally consumes only files copied into the
release index, not the development tree's build outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
from typing import Any


SCHEMA_VERSION = 1
KIND = "qperiapt.local_release_index"
FORBIDDEN_INDEX_TEXT = (
    "artifact/device-runs",
    ".mobileprovision",
    ".xcresult",
    "ProvisionedDevices",
    "TeamIdentifier",
    "000081",
    "emulator-",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: cannot parse JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc
    return h.hexdigest()


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from None


def require_relative_safe(path: str, label: str) -> None:
    require(path and not path.startswith(("/", "\\")), f"{label} must be a relative path: {path}")
    parts = pathlib.PurePosixPath(path).parts
    require(".." not in parts, f"{label} must not contain '..': {path}")


def default_index_path(root: pathlib.Path) -> pathlib.Path:
    target = root / "target"
    latest = target / "qperiapt-local-release" / "latest.json"
    payload = load_json(latest)
    require(payload.get("kind") == "qperiapt.local_release_index.pointer", "latest release pointer kind mismatch")
    rel = payload.get("index_path")
    expected = payload.get("index_sha256")
    require(isinstance(rel, str), "latest release pointer lacks index_path")
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "latest release pointer lacks a valid index_sha256")
    require_relative_safe(rel, "latest release index path")
    index_path = (target / rel).resolve()
    require_under(index_path, target, "latest release index")
    require(index_path.is_file(), f"latest release index missing: {index_path}")
    require(sha256_file(index_path) == expected, "latest release pointer hash mismatch")
    return index_path


def resolve_index_path(root: pathlib.Path, raw: str) -> pathlib.Path:
    if not raw:
        return default_index_path(root)
    index_path = pathlib.Path(raw)
    if not index_path.is_absolute():
        index_path = root / index_path
    index_path = index_path.resolve()
    require(index_path.is_file(), f"release index missing: {index_path}")
    require_under(index_path, root / "target" / "qperiapt-local-release", "release index")
    return index_path


def validate_index_text(index_path: pathlib.Path) -> None:
    text = read_text(index_path)
    for forbidden in FORBIDDEN_INDEX_TEXT:
        require(forbidden not in text, f"release index contains private/local token: {forbidden}")


def verify_sha256s(base: pathlib.Path) -> None:
    sums = base / "SHA256SUMS"
    require(sums.is_file(), f"missing SHA256SUMS: {sums}")
    for line_no, line in enumerate(read_text(sums).splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split()
        require(len(parts) == 2, f"malformed SHA256SUMS line {line_no}: {line}")
        expected, rel = parts
        require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, f"malformed sha256 at {sums}:{line_no}")
        require_relative_safe(rel, f"SHA256SUMS path at {sums}:{line_no}")
        target = (base / rel).resolve()
        require_under(target, base, f"SHA256SUMS path at {sums}:{line_no}")
        require(target.is_file(), f"SHA256SUMS target missing: {target}")
        require(sha256_file(target) == expected, f"SHA256SUMS hash mismatch for {target}")


def verify_index_file(release_root: pathlib.Path, item: Any) -> pathlib.Path:
    require(isinstance(item, dict), "indexed file entry is not an object")
    rel = item.get("path")
    expected = item.get("sha256")
    require(isinstance(rel, str), "indexed file path is missing")
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None, f"indexed file hash is malformed: {rel}")
    require_relative_safe(rel, "indexed file path")
    path = (release_root / rel).resolve()
    require_under(path, release_root, "indexed file")
    require(path.is_file(), f"indexed file missing: {path}")
    require(sha256_file(path) == expected, f"indexed file hash mismatch: {rel}")
    return path


def verify_index(index_path: pathlib.Path) -> dict[str, Any]:
    release_root = index_path.parent
    index = load_json(index_path)
    require(index.get("schema_version") == SCHEMA_VERSION, "unsupported release index schema")
    require(index.get("kind") == KIND, "release index kind mismatch")
    validate_index_text(index_path)
    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "release index lacks artifacts")
    for artifact in artifacts:
        require(isinstance(artifact, dict), "artifact entry is malformed")
        files = artifact.get("files")
        require(isinstance(files, list) and files, f"artifact {artifact.get('id')} lacks files")
        for item in files:
            verify_index_file(release_root, item)
        verify_index_file(release_root, artifact.get("manifest"))
        verify_index_file(release_root, artifact.get("sha256s"))
    verify_sha256s(release_root)
    return index


def c_archive_entries(index: dict[str, Any], release_root: pathlib.Path) -> list[pathlib.Path]:
    entries: list[pathlib.Path] = []
    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list), "release index artifacts are malformed")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("face") != "c-abi" or artifact.get("type") != "tar.gz":
            continue
        files = artifact.get("files")
        require(isinstance(files, list) and files, f"C ABI artifact {artifact.get('id')} lacks files")
        for item in files:
            path = verify_index_file(release_root, item)
            if path.name.endswith(".tar.gz"):
                entries.append(path)
    require(entries, "release index has no C ABI tar.gz artifact")
    return entries


def safe_extract_tar_gz(archive: pathlib.Path, dest: pathlib.Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                name = member.name
                require(name, f"empty tar member in {archive}")
                pure = pathlib.PurePosixPath(name)
                require(not pure.is_absolute(), f"absolute tar member in {archive}: {name}")
                require(".." not in pure.parts, f"parent traversal tar member in {archive}: {name}")
                require(member.isfile() or member.isdir(), f"unsupported tar member type in {archive}: {name}")
                target = (dest / pure).resolve()
                require_under(target, dest, "tar extraction target")
            tf.extractall(dest)
    except tarfile.TarError as exc:
        raise SystemExit(f"error: cannot extract {archive}: {exc}") from exc


def find_c_package_root(extract_root: pathlib.Path) -> pathlib.Path:
    candidates = []
    for path in extract_root.rglob("lib/pkgconfig/qperiapt.pc"):
        package_root = path.parents[2]
        if (package_root / "share/q-periapt/smoke.c").is_file() and (package_root / "SHA256SUMS").is_file():
            candidates.append(package_root)
    require(len(candidates) == 1, f"expected exactly one C package root, found {len(candidates)}")
    return candidates[0]


def need_tool(name: str) -> str:
    path = shutil.which(name)
    require(path is not None, f"required tool not found: {name}")
    return path


def run_cmd(args: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None) -> str:
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
    out = run_cmd(args, cwd=package_root, env=env)
    return shlex.split(out)


def runtime_env(package_root: pathlib.Path) -> dict[str, str]:
    env = os.environ.copy()
    lib_dir = str(package_root / "lib")
    for key in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        old = env.get(key)
        env[key] = lib_dir if not old else f"{lib_dir}{os.pathsep}{old}"
    return env


def compile_and_run_c_smoke(package_root: pathlib.Path, work: pathlib.Path, cc: str, label: str, flags: list[str]) -> None:
    out = work / f"qperiapt_c_{label}_smoke"
    cmd = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "share/q-periapt/smoke.c", *flags, "-o", str(out)]
    run_cmd(cmd, cwd=package_root)
    output = run_cmd([str(out)], cwd=package_root, env=runtime_env(package_root))
    require("ALL PASS" in output, f"C {label} smoke did not print ALL PASS")


def smoke_c_archive(root: pathlib.Path, index_path: pathlib.Path, archive: pathlib.Path, out_dir: pathlib.Path) -> None:
    index_sha = sha256_file(index_path)
    work = out_dir / index_sha[:16] / archive.name.removesuffix(".tar.gz")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    safe_extract_tar_gz(archive, work / "extract")
    package_root = find_c_package_root(work / "extract")
    verify_sha256s(package_root)
    cc = need_tool("cc")
    need_tool("pkg-config")
    system = platform.system()
    require(system in {"Darwin", "Linux"}, f"C release consumer smoke supports Darwin/Linux hosts, got {system}")
    compile_and_run_c_smoke(package_root, work, cc, "dynamic", pkg_config(package_root, "qperiapt", static=False))
    compile_and_run_c_smoke(package_root, work, cc, "static", pkg_config(package_root, "qperiapt-static", static=True))
    require_under(work, root / "target", "release consumer smoke output")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--index", default=os.environ.get("QPERIAPT_RELEASE_INDEX_PATH", ""))
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    target = root / "target"
    out_dir = pathlib.Path(args.out_dir).resolve() if args.out_dir else target / "qperiapt-release-consumer-smoke"
    require_under(out_dir, target, "release consumer smoke output")
    index_path = resolve_index_path(root, args.index)
    index = verify_index(index_path)
    release_root = index_path.parent
    for archive in c_archive_entries(index, release_root):
        smoke_c_archive(root, index_path, archive, out_dir)
    print("QPERIAPT_RELEASE_CONSUMER_SMOKE_PASS c-abi")


if __name__ == "__main__":
    main()
