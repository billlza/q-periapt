"""Isolated source-only dispatcher for repository Python tooling.

This file is executed directly by ``/usr/bin/python3 -I -S -B``.  It adds only
the canonical repository roots needed by local verifier imports, after the
standard-library paths, and supports the small Python CLI surface used by the
shell gates.
"""

from __future__ import annotations

import os
import pathlib
import runpy
import sys
from collections.abc import Sequence


ARTIFACT_DIR = pathlib.Path(__file__).resolve(strict=True).parent
REPOSITORY_ROOT = ARTIFACT_DIR.parent


def _add_repository_import_roots() -> None:
    for path in (ARTIFACT_DIR, REPOSITORY_ROOT):
        value = str(path)
        if value not in sys.path:
            # Preserve the isolated interpreter's standard-library precedence.
            sys.path.append(value)


def _clear_python_environment() -> None:
    for name in tuple(os.environ):
        if name.startswith("PYTHON"):
            del os.environ[name]


def _execute(code: bytes | str, filename: str, argv: list[str]) -> None:
    sys.argv = argv
    namespace = {
        "__builtins__": __builtins__,
        "__name__": "__main__",
        "__package__": None,
        "__spec__": None,
    }
    exec(compile(code, filename, "exec"), namespace, namespace)


def dispatch(arguments: Sequence[str]) -> None:
    if not arguments:
        raise SystemExit("error: hardened Python launcher requires -, -c, -m, or a script path")

    _clear_python_environment()
    _add_repository_import_roots()
    mode = arguments[0]
    if mode == "-":
        _execute(sys.stdin.buffer.read(), "<stdin>", ["-", *arguments[1:]])
        return
    if mode == "-c":
        if len(arguments) < 2:
            raise SystemExit("error: hardened Python launcher -c requires code")
        _execute(arguments[1], "<string>", ["-c", *arguments[2:]])
        return
    if mode == "-m":
        if len(arguments) < 2 or not arguments[1]:
            raise SystemExit("error: hardened Python launcher -m requires a module")
        sys.argv = [arguments[1], *arguments[2:]]
        runpy.run_module(arguments[1], run_name="__main__", alter_sys=True)
        return
    if mode.startswith("-"):
        raise SystemExit(f"error: unsupported hardened Python option: {mode}")

    script = pathlib.Path(mode)
    if script.is_symlink():
        raise SystemExit(f"error: Python script must not be a symlink: {script}")
    try:
        resolved = script.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"error: Python script is unavailable: {script}: {exc}") from exc
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError as exc:
        raise SystemExit(
            f"error: Python script must stay inside the repository: {resolved}"
        ) from exc
    if not resolved.is_file():
        raise SystemExit(f"error: Python script must be a non-symlink regular file: {resolved}")
    sys.argv = [mode, *arguments[1:]]
    runpy.run_path(str(resolved), run_name="__main__")


if __name__ == "__main__":
    dispatch(sys.argv[1:])
