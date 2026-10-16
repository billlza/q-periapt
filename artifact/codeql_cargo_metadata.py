"""Preserve host build dependencies when CodeQL requests WASM-filtered metadata.

Only the metadata dependency graph changes. Compilation arguments, cfg values,
standard streams and Cargo's exit status pass through without modification.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys

from evidence_io import parse_strict_json_bytes, read_regular_snapshot


def rewrite_metadata(arguments: list[str], host: str, roots: list[Path], cwd: Path) -> list[str]:
    if not arguments or len(arguments) > 128 or sum(map(len, arguments)) > 16384:
        raise ValueError("analysis Cargo argument boundary exceeded")
    if arguments[0] != "metadata":
        return list(arguments)
    filters = []
    manifest = None
    for index, argument in enumerate(arguments):
        name, separator, value = argument.partition("=")
        if name not in ("--filter-platform", "--manifest-path"):
            continue
        if not separator:
            if index + 1 == len(arguments):
                raise ValueError("analysis Cargo option is missing its value")
            value = arguments[index + 1]
        if name == "--filter-platform":
            filters.append(value)
        else:
            if manifest is not None:
                raise ValueError("duplicate analysis manifest option")
            manifest = value
    target = "wasm32-unknown-unknown"
    if target not in filters:
        return list(arguments)
    if filters not in ([target], [target, host]):
        raise ValueError("unexpected cross-target metadata filter set")
    location = Path(manifest) if manifest is not None else Path("Cargo.toml")
    location = (location if location.is_absolute() else cwd / location).resolve()
    if not any(location.is_relative_to(root) for root in roots):
        raise ValueError("cross-target metadata manifest is outside the analysis roots")
    return [*arguments, "--filter-platform", host] if host not in filters else list(arguments)


def main() -> None:
    if len(sys.argv) < 3:
        raise ValueError("expected a settings path and Cargo arguments")
    path = Path(sys.argv[1])
    settings = parse_strict_json_bytes(
        read_regular_snapshot(path, maximum=16384, label="analysis Cargo settings").data,
        label="analysis Cargo settings",
    )
    if (not isinstance(settings, dict) or set(settings) != {"cargo", "host", "roots", "audit"}
            or settings["host"] not in ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin")
            or not isinstance(settings["roots"], list) or not settings["roots"]
            or not all(isinstance(root, str) and Path(root).is_absolute() for root in settings["roots"])
            or not all(isinstance(settings[key], str) and Path(settings[key]).is_absolute()
                       for key in ("cargo", "audit"))):
        raise ValueError("invalid analysis Cargo settings")
    original = sys.argv[2:]
    rewritten = rewrite_metadata(original, settings["host"],
                                 [Path(root).resolve(strict=True) for root in settings["roots"]],
                                 Path.cwd())
    def digest(arguments):
        return hashlib.sha256(json.dumps(arguments, separators=(",", ":")).encode()).hexdigest()
    record = json.dumps({"command": original[0], "original_argv_sha256": digest(original),
                         "executed_argv_sha256": digest(rewritten),
                         "host_filter_added": original != rewritten}, sort_keys=True).encode() + b"\n"
    descriptor = os.open(settings["audit"], os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if os.fstat(descriptor).st_size + len(record) > 1024 * 1024:
            raise ValueError("analysis Cargo audit exceeds its bound")
        if os.write(descriptor, record) != len(record):
            raise ValueError("incomplete analysis Cargo audit write")
    finally:
        os.close(descriptor)
    os.execv(settings["cargo"], [settings["cargo"], *rewritten])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        sys.exit("error: analysis Cargo metadata: " + str(exc))
