#!/usr/bin/env python3
"""Deterministic, caller-environment-independent Git provenance checks."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import subprocess
from dataclasses import dataclass
from typing import Sequence

from evidence_io import EvidenceIOError, read_regular_snapshot


GIT = "/usr/bin/git"
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
MAX_TRACKED_FILE_BYTES = 512 * 1024 * 1024
GENERATED_EVIDENCE_PATHS = frozenset(
    {"artifact/results.json", "paper/camera-ready-results.txt"}
)


class GitProvenanceError(ValueError):
    """Git metadata or actual worktree bytes cannot support provenance."""


@dataclass(frozen=True, slots=True)
class WorktreeInspection:
    commit: str
    dirty: bool
    reasons: tuple[str, ...]


def _repository_root(root: pathlib.Path) -> pathlib.Path:
    try:
        resolved = pathlib.Path(root).resolve(strict=True)
    except OSError as exc:
        raise GitProvenanceError(f"cannot resolve repository root {root}: {exc}") from exc
    git_dir = resolved / ".git"
    try:
        metadata = git_dir.lstat()
    except OSError as exc:
        raise GitProvenanceError(f"repository lacks a readable .git directory: {resolved}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or git_dir.is_symlink():
        raise GitProvenanceError(
            f"release provenance requires a non-symlink .git directory: {git_dir}"
        )
    return resolved


def _environment() -> dict[str, str]:
    # Start from an allowlist.  In particular, no caller-controlled GIT_* value,
    # HOME, executable search path, locale, or repository selector is inherited.
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def run_git_bytes(root: pathlib.Path, args: Sequence[str]) -> bytes:
    """Run fixed Git against an explicit git-dir/worktree with a minimal environment."""

    resolved = _repository_root(root)
    command = [
        GIT,
        f"--git-dir={resolved / '.git'}",
        f"--work-tree={resolved}",
        "-c",
        f"safe.directory={resolved}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        *args,
    ]
    try:
        process = subprocess.run(
            command,
            cwd=resolved,
            env=_environment(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            detail = exc.stderr.decode("utf-8", errors="replace").strip()
        suffix = f": {detail}" if detail else ""
        raise GitProvenanceError(f"git {' '.join(args)} failed{suffix}") from exc
    return process.stdout


def run_git_text(root: pathlib.Path, args: Sequence[str]) -> str:
    try:
        return run_git_bytes(root, args).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise GitProvenanceError(f"git {' '.join(args)} returned non-UTF-8 output") from exc


def git_commit(root: pathlib.Path) -> str:
    commit = run_git_text(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if COMMIT_RE.fullmatch(commit) is None:
        raise GitProvenanceError(f"git commit hash is malformed: {commit}")
    return commit


def require_commit_or_evidence_successor(root: pathlib.Path, proof_commit: str) -> str:
    """Accept the exact commit or a successor changing only generated evidence roots."""

    if COMMIT_RE.fullmatch(proof_commit) is None:
        raise GitProvenanceError(f"proof commit hash is malformed: {proof_commit}")
    current = git_commit(root)
    if proof_commit == current:
        return current
    merge_base = run_git_text(root, ["merge-base", proof_commit, current])
    if merge_base != proof_commit:
        raise GitProvenanceError(
            f"proof commit {proof_commit} is not an ancestor of current commit {current}"
        )
    changed = _decode_nul_paths(
        run_git_bytes(root, ["diff", "--name-only", "-z", proof_commit, current, "--"]),
        "proof-to-current commit diff",
    )
    unexpected = sorted(set(changed) - GENERATED_EVIDENCE_PATHS)
    if not changed or unexpected:
        detail = unexpected[:8] if unexpected else ["empty diff"]
        raise GitProvenanceError(
            "successor commit changes canonical source inputs: " + ", ".join(detail)
        )
    return current


def repository_paths(root: pathlib.Path) -> list[str]:
    resolved = _repository_root(root)
    unsafe_gitignore = _unsafe_gitignore_paths(root)
    if unsafe_gitignore:
        raise GitProvenanceError(
            "repository contains untracked .gitignore files that could hide execution inputs: "
            + ", ".join(unsafe_gitignore[:8])
        )
    python_caches = _repository_python_cache_paths(root)
    if python_caches:
        raise GitProvenanceError(
            "repository contains Python bytecode caches that could replace source imports: "
            + ", ".join(python_caches[:8])
        )
    tracked = _decode_nul_paths(
        run_git_bytes(root, ["ls-files", "--cached", "-z"]),
        "tracked source-input inventory",
    )
    return _materialized_tracked_paths(resolved, tracked) + _untracked_execution_input_paths(
        resolved
    )


def _materialized_tracked_paths(root: pathlib.Path, paths: Sequence[str]) -> list[str]:
    """Return tracked regular files that exist in the actual dirty worktree.

    Git's cached inventory intentionally retains unstaged deletions.  A canonical
    digest of *current* bytes must encode such a deletion as path absence, while
    ``inspect_worktree`` independently records the deletion as dirty provenance.
    Every materialized component remains subject to a no-symlink, regular-file
    policy so that filtering absent entries cannot weaken the input boundary.
    """

    materialized: list[str] = []
    for relative in paths:
        pure = pathlib.PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
            raise GitProvenanceError(f"tracked path is not canonical: {relative}")
        current = root
        missing = False
        for index, component in enumerate(pure.parts):
            current /= component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                missing = True
                break
            except OSError as exc:
                raise GitProvenanceError(
                    f"cannot inspect tracked source-input path {relative}: {exc}"
                ) from exc
            final = index == len(pure.parts) - 1
            expected_type = stat.S_ISREG if final else stat.S_ISDIR
            if current.is_symlink() or not expected_type(metadata.st_mode):
                kind = "regular file" if final else "directory"
                raise GitProvenanceError(
                    f"tracked source-input path requires a non-symlink {kind}: {relative}"
                )
        if not missing:
            materialized.append(relative)
    return materialized


def _decode_nul_paths(raw: bytes, label: str) -> list[str]:
    try:
        return [part.decode("utf-8") for part in raw.split(b"\0") if part]
    except UnicodeDecodeError as exc:
        raise GitProvenanceError(f"{label} contains a non-UTF-8 path") from exc


def _unsafe_gitignore_paths(root: pathlib.Path) -> list[str]:
    # Do not apply an exclude source while finding untracked .gitignore files:
    # this returns visible, nested, and self-hidden variants alike.  The fixed
    # Git invocation also disables caller/global excludes.
    raw = run_git_bytes(
        root,
        [
            "ls-files",
            "--others",
            "-z",
            "--",
            ".gitignore",
            ":(glob)**/.gitignore",
        ],
    )
    paths = _decode_nul_paths(raw, "untracked .gitignore inventory")
    return [path for path in paths if not _is_declared_ephemeral_output(path)]


def _repository_python_cache_paths(root: pathlib.Path) -> list[str]:
    # No exclude source is applied, so ignored bytecode is still returned.
    raw = run_git_bytes(
        root,
        [
            "ls-files",
            "--cached",
            "--others",
            "-z",
            "--",
            ":(glob)**/*.pyc",
            ":(glob)**/*.pyo",
            ":(glob)**/__pycache__/**",
        ],
    )
    return _decode_nul_paths(raw, "repository Python bytecode-cache inventory")


def _is_declared_ephemeral_output(relative: str) -> bool:
    """Apply the fixed, verifier-owned output policy without consulting Git ignores."""

    pure = pathlib.PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
        raise GitProvenanceError(f"untracked path is not canonical: {relative}")
    parts = pure.parts
    if not parts:
        raise GitProvenanceError("untracked source-input path is empty")
    if parts[0] in {"target", "tmp"}:
        return True
    fixed_prefixes = (
        ("artifact", "device-runs"),
        ("bindings", "swift", ".build"),
        ("bindings", "kotlin", ".gradle"),
        ("bindings", "kotlin", "build"),
        ("crates", "q-periapt-wasm", "pkg"),
        ("research", "hqc-fips207-candidate", "target"),
        ("fuzz", "corpus"),
        ("fuzz", "artifacts"),
        ("fuzz", "coverage"),
    )
    if any(parts[: len(prefix)] == prefix for prefix in fixed_prefixes):
        return True
    if len(parts) >= 3 and parts[:2] == ("bindings", "apple-device") and parts[2].endswith(
        ".xcodeproj"
    ):
        return True
    if parts[0] == "sbom" and (pure.suffix == ".json" or relative.endswith(".cdx.json")):
        return True
    return False


def _untracked_execution_input_paths(root: pathlib.Path) -> list[str]:
    # With no --exclude/--ignored option, Git reports ignored files too.  Only
    # the verifier-owned policy above may remove a path from the source digest.
    paths = _decode_nul_paths(
        run_git_bytes(root, ["ls-files", "--others", "-z"]),
        "untracked source-input inventory",
    )
    return [path for path in paths if not _is_declared_ephemeral_output(path)]


def _parse_index(root: pathlib.Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for record in run_git_bytes(root, ["ls-files", "--stage", "-z"]).split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GitProvenanceError("git index entry is malformed") from exc
        if stage != "0" or path in entries:
            raise GitProvenanceError(f"git index has an unmerged or duplicate entry: {path}")
        entries[path] = (mode, object_id)
    return entries


def _parse_head(root: pathlib.Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for record in run_git_bytes(root, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"]).split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GitProvenanceError("HEAD tree entry is malformed") from exc
        if object_type not in {"blob", "commit"} or path in entries:
            raise GitProvenanceError(f"HEAD tree has an unsupported or duplicate entry: {path}")
        entries[path] = (mode, object_id)
    return entries


def _special_index_flags(root: pathlib.Path) -> list[str]:
    flagged: list[str] = []
    for record in run_git_bytes(root, ["ls-files", "-v", "-z"]).split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" ":
            raise GitProvenanceError("git index flag output is malformed")
        try:
            path = record[2:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitProvenanceError("git index flag path is not UTF-8") from exc
        tag = chr(record[0])
        if tag != "H":
            flagged.append(f"{tag}:{path}")
    return flagged


def _blob_id(data: bytes, algorithm: str) -> str:
    if algorithm not in {"sha1", "sha256"}:
        raise GitProvenanceError(f"unsupported Git object format: {algorithm}")
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def inspect_worktree(root: pathlib.Path) -> WorktreeInspection:
    """Compare HEAD, index metadata, and actual tracked bytes without Git stat shortcuts."""

    resolved = _repository_root(root)
    commit = git_commit(resolved)
    reasons: list[str] = []
    index = _parse_index(resolved)
    head = _parse_head(resolved)
    if index != head:
        reasons.append("index differs from HEAD")
    flagged = _special_index_flags(resolved)
    if flagged:
        reasons.append(f"special index flags present: {', '.join(flagged[:8])}")
    hidden_gitignore = _unsafe_gitignore_paths(resolved)
    if hidden_gitignore:
        reasons.append(
            "untracked .gitignore files can hide execution inputs: "
            + ", ".join(hidden_gitignore[:8])
        )
    python_caches = _repository_python_cache_paths(resolved)
    if python_caches:
        reasons.append(
            "repository Python bytecode caches can replace source imports: "
            + ", ".join(python_caches[:8])
        )
    untracked = _untracked_execution_input_paths(resolved)
    if untracked:
        reasons.append(f"untracked source-input paths present: {len(untracked)}")

    object_format = run_git_text(resolved, ["rev-parse", "--show-object-format"])
    for relative, (mode, expected_id) in sorted(index.items()):
        pure = pathlib.PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
            raise GitProvenanceError(f"tracked path is not canonical: {relative}")
        if mode not in {"100644", "100755"}:
            reasons.append(f"unsupported tracked mode {mode}: {relative}")
            continue
        path = resolved.joinpath(*pure.parts)
        try:
            snapshot = read_regular_snapshot(
                path,
                maximum=MAX_TRACKED_FILE_BYTES,
                label=f"tracked file {relative}",
            )
        except EvidenceIOError as exc:
            reasons.append(str(exc))
            continue
        actual_id = _blob_id(snapshot.data, object_format)
        if actual_id != expected_id:
            reasons.append(f"tracked bytes differ from HEAD: {relative}")
        executable = bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if executable != (mode == "100755"):
            reasons.append(f"tracked executable mode differs from HEAD: {relative}")
    return WorktreeInspection(commit=commit, dirty=bool(reasons), reasons=tuple(reasons))


def source_tree_dirty(root: pathlib.Path) -> bool:
    return inspect_worktree(root).dirty
