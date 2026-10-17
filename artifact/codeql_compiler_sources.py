"""Read tracked source dependencies from successful Cargo JSON build artifacts.

Each artifact selects its own rustc depfile. Scanning a shared target directory
would mix stale artifacts and relative paths from different workspace roots.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import shlex

from codeql_rust_quality import CodeQLRustQualityError
from evidence_io import EvidenceIOError, parse_strict_json_bytes, read_regular_snapshot


def _snapshot(path: Path, maximum: int, label: str):
    try:
        return read_regular_snapshot(path, maximum=maximum, label=label)
    except EvidenceIOError as exc:
        raise CodeQLRustQualityError(f"cannot bind {label}: {exc}") from exc


def _dependencies(data: bytes, cwd: Path) -> tuple[Path, ...]:
    try:
        text = data.decode("utf-8").replace("\\\n", "")
        paths = []
        for line in text.splitlines():
            if not line or line.startswith("#") or line.endswith(":"):
                continue
            if ": " not in line:
                raise ValueError("unsupported depfile rule")
            for token in shlex.split(line.partition(": ")[2]):
                path = Path(token)
                paths.append((path if path.is_absolute() else cwd / path).resolve(strict=True))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CodeQLRustQualityError(f"cannot read compiler source dependencies: {exc}") from exc
    if not paths:
        raise CodeQLRustQualityError("compiler depfile has no source dependencies")
    return tuple(paths)


def _depfile_candidates(filenames: list[str], kinds: list[str]) -> set[Path]:
    candidates = set()
    for filename in filenames:
        artifact = Path(filename)
        if not artifact.is_absolute():
            raise CodeQLRustQualityError("Cargo artifact filename must be absolute")
        if "custom-build" in kinds:
            candidates.update(artifact.parent.glob("*.d"))
        else:
            stem = artifact.stem if artifact.suffix in (".rmeta", ".rlib", ".a", ".so", ".dylib") else artifact.name
            if artifact.suffix in (".rmeta", ".rlib", ".a", ".so", ".dylib") and stem.startswith("lib"):
                stem = stem[3:]
            candidates.add(artifact.with_name(stem + ".d"))
    if not candidates or len(candidates) > 16:
        raise CodeQLRustQualityError("Cargo artifact has no bounded depfile candidates")
    return candidates


def collect_compiled_sources(
    root: Path, cwd: Path, cargo_stdout: bytes, tracked_sha256: Mapping[str, str]
) -> dict[str, str]:
    root = root.resolve(strict=True)
    cwd = cwd.resolve(strict=True)
    if not cwd.is_relative_to(root) or len(cargo_stdout) > 32 * 1024 * 1024:
        raise CodeQLRustQualityError("compiler command context is outside its source boundary")
    compiled = {}
    finished = 0
    workspace_artifacts = 0
    for line in cargo_stdout.splitlines():
        event = parse_strict_json_bytes(line, label="Cargo compiler message")
        if not isinstance(event, dict):
            raise CodeQLRustQualityError("Cargo compiler event is not an object")
        reason = event.get("reason")
        if reason == "build-finished":
            if event.get("success") is not True:
                raise CodeQLRustQualityError("Cargo compilation did not succeed")
            finished += 1
        elif reason == "compiler-message":
            message = event.get("message")
            if not isinstance(message, dict) or message.get("level") not in ("note", "help"):
                raise CodeQLRustQualityError("Cargo emitted a warning or error diagnostic")
        elif reason == "compiler-artifact":
            target = event.get("target")
            filenames = event.get("filenames")
            if (not isinstance(target, dict) or not isinstance(target.get("src_path"), str)
                    or not isinstance(target.get("kind"), list)
                    or not all(isinstance(kind, str) for kind in target["kind"])
                    or not isinstance(filenames, list) or not filenames
                    or not all(isinstance(path, str) for path in filenames)):
                raise CodeQLRustQualityError("Cargo emitted a malformed artifact")
            crate_source = Path(target["src_path"])
            if not crate_source.is_absolute():
                raise CodeQLRustQualityError("Cargo crate source must be absolute")
            crate_source = crate_source.resolve(strict=True)
            if not crate_source.is_relative_to(root):
                continue
            relative_crate = crate_source.relative_to(root).as_posix()
            if relative_crate not in tracked_sha256:
                raise CodeQLRustQualityError("Cargo compiled an untracked crate source")
            workspace_artifacts += 1
            matches = []
            for depfile in sorted(_depfile_candidates(filenames, target["kind"])):
                snapshot = _snapshot(depfile, 2 * 1024 * 1024, "compiler source depfile")
                dependencies = _dependencies(snapshot.data, cwd)
                if dependencies[0] == crate_source:
                    matches.append(dependencies)
            if not matches or any(match != matches[0] for match in matches[1:]):
                raise CodeQLRustQualityError("compiler depfile does not uniquely bind the crate source")
            for path in matches[0]:
                if not path.is_relative_to(root) or path.suffix != ".rs":
                    continue
                relative = path.relative_to(root).as_posix()
                if relative not in tracked_sha256:
                    raise CodeQLRustQualityError("compiler read an untracked Rust source")
                snapshot = _snapshot(path, 5 * 1024 * 1024, "compiled Rust source")
                if snapshot.sha256 != tracked_sha256[relative]:
                    raise CodeQLRustQualityError("compiled source bytes differ from the analysis input")
                compiled[relative] = snapshot.sha256
        elif reason != "build-script-executed":
            raise CodeQLRustQualityError(f"unexpected Cargo compiler event: {reason!r}")
    if finished != 1 or not workspace_artifacts or not compiled:
        raise CodeQLRustQualityError("Cargo result lacks one successful, nonempty compilation")
    return compiled
