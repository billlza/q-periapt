#!/usr/bin/env python3
"""Fail closed on accidental formal-tool version drift.

This is a Level-1 release-integrity check over the selected local executables.
It does not attest executable bytes or defend against replacement by an actor
that can modify files under the same account while the check is running.  The
CI jobs retain their separate source/archive pins; this module gives local and
CI entrypoints one semantic version authority and one strict output parser.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from collections.abc import Callable, Sequence
from typing import Literal, Never

from bounded_process import BoundedProcessError, BoundedResult, capture_output


EXPECTED_EASYCRYPT_SOURCE_COMMIT = (
    "50ae51d106dfb6611235f4a8bb7f46275d34a38d"
)
EXPECTED_EASYCRYPT_CONFIG_GIT_HASH = (
    "r2026.06-6-g" + EXPECTED_EASYCRYPT_SOURCE_COMMIT[:7]
)
EXPECTED_EASYCRYPT_CONFIG_LINE = (
    f"git-hash: {EXPECTED_EASYCRYPT_CONFIG_GIT_HASH}"
)
EXPECTED_TAMARIN_VERSION = "1.12.0"
EXPECTED_MAUDE_VERSION = "3.5.1"
EXPECTED_PROVERIF_VERSION = "2.05"

COMMAND_TIMEOUT_SECONDS = 30
MAXIMUM_STDOUT_BYTES = 64 * 1024
MAXIMUM_STDERR_BYTES = 64 * 1024

ToolSelection = Literal["all", "easycrypt", "tamarin", "proverif"]
Runner = Callable[..., BoundedResult]

_SELECTION_TO_EXECUTABLES: dict[ToolSelection, tuple[str, ...]] = {
    "all": ("easycrypt", "tamarin-prover", "maude", "proverif"),
    "easycrypt": ("easycrypt",),
    "tamarin": ("tamarin-prover", "maude"),
    "proverif": ("proverif",),
}
_SELECTION_TO_MARKER_TOOLS: dict[ToolSelection, tuple[str, ...]] = {
    "all": ("easycrypt", "tamarin", "maude", "proverif"),
    "easycrypt": ("easycrypt",),
    "tamarin": ("tamarin", "maude"),
    "proverif": ("proverif",),
}
_FIXED_IDENTITY_COMMANDS = frozenset(
    {
        ("easycrypt", "config"),
        ("tamarin-prover", "--version"),
        ("maude", "--version"),
        ("proverif", "-help"),
    }
)
_FIXED_EXECUTABLE_NAMES = frozenset(
    command[0] for command in _FIXED_IDENTITY_COMMANDS
)
_PROVERIF_VERSION_LINE = re.compile(
    r"^Proverif (?P<version>[0-9]+\.[0-9]+)\. "
    r"Cryptographic protocol verifier, by .+$"
)
_DIAGNOSTIC_LINE = re.compile(r"^\s*(?:warning|error)(?::|\[|\s)", re.I)


class FormalToolchainContractError(RuntimeError):
    """One selected formal tool does not satisfy the fixed release contract."""


def _fail(message: str) -> Never:
    raise FormalToolchainContractError(message)


def _path_environment(value: str | None) -> str:
    selected = os.environ.get("PATH") if value is None else value
    if not isinstance(selected, str) or not selected or "\x00" in selected:
        _fail("formal tool PATH is unavailable or malformed")
    entries = selected.split(os.pathsep)
    if any(not entry or not pathlib.Path(entry).is_absolute() for entry in entries):
        _fail("formal tool PATH must contain only non-empty absolute entries")
    return selected


def _minimal_environment(path_environment: str) -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": path_environment,
    }


def _run_identity_command(
    executable: str,
    arguments: Sequence[str],
    *,
    label: str,
    path_environment: str,
    runner: Runner,
) -> tuple[str, str]:
    command = (executable, *arguments)
    if command not in _FIXED_IDENTITY_COMMANDS:
        _fail("formal tool identity command is not one fixed contract command")
    try:
        result = runner(
            command,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            maximum_stdout_bytes=MAXIMUM_STDOUT_BYTES,
            maximum_stderr_bytes=MAXIMUM_STDERR_BYTES,
            environment=_minimal_environment(path_environment),
        )
    except BoundedProcessError as exc:
        raise FormalToolchainContractError(
            f"{label} bounded process {exc.kind}: {exc}"
        ) from exc
    if (
        not isinstance(result, BoundedResult)
        or type(result.returncode) is not int
        or not isinstance(result.stdout, bytes)
        or not isinstance(result.stderr, bytes)
    ):
        _fail(f"{label} returned a malformed bounded-process result")
    if result.returncode != 0:
        _fail(f"{label} exited with status {result.returncode}")
    try:
        stdout = result.stdout.decode("utf-8", errors="strict")
        stderr = result.stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FormalToolchainContractError(
            f"{label} output is not UTF-8"
        ) from exc
    if "\x00" in stdout or "\x00" in stderr:
        _fail(f"{label} output contains a NUL byte")
    return stdout, stderr


def _require_empty_stream(output: str, *, label: str) -> None:
    if output:
        _fail(f"{label} wrote unexpected output")


def _reject_diagnostics(lines: Sequence[str], label: str) -> None:
    if any(_DIAGNOSTIC_LINE.match(line) is not None for line in lines):
        _fail(f"{label} output contains an error or warning diagnostic")


def parse_easycrypt_config(output: str) -> None:
    """Require the one exact EasyCrypt source identity line."""

    lines = output.splitlines()
    _reject_diagnostics(lines, "EasyCrypt config")
    identity_lines = [line for line in lines if line.startswith("git-hash:")]
    if identity_lines != [EXPECTED_EASYCRYPT_CONFIG_LINE]:
        _fail("EasyCrypt config does not contain the one expected git-hash")


def parse_tamarin_version(output: str) -> None:
    """Require one exact Tamarin version and its reported Maude version."""

    lines = output.splitlines()
    _reject_diagnostics(lines, "Tamarin version")
    tamarin_lines = [line for line in lines if line.startswith("Tamarin version ")]
    maude_lines = [line for line in lines if line.startswith("Maude version ")]
    if tamarin_lines != [f"Tamarin version {EXPECTED_TAMARIN_VERSION}"]:
        _fail("Tamarin output does not contain the one expected version")
    if maude_lines != [f"Maude version {EXPECTED_MAUDE_VERSION}"]:
        _fail("Tamarin output does not report the one expected Maude version")


def parse_tamarin_diagnostics(output: str) -> None:
    """Require Tamarin's exact successful Maude discovery diagnostics."""

    lines = output.splitlines()
    _reject_diagnostics(lines, "Tamarin diagnostics")
    expected = [
        "maude tool: 'maude'",
        f" checking version: {EXPECTED_MAUDE_VERSION}. OK.",
        " checking installation: OK.",
    ]
    if lines != expected:
        _fail("Tamarin diagnostics do not report the expected Maude health")


def parse_maude_version(output: str) -> None:
    """Require Maude's exact single-line version output."""

    lines = output.splitlines()
    _reject_diagnostics(lines, "Maude version")
    if lines != [EXPECTED_MAUDE_VERSION]:
        _fail("Maude output is not the exact expected version")


def parse_proverif_help(output: str) -> None:
    """Extract and require the exact ProVerif version from its supported help CLI."""

    lines = output.splitlines()
    _reject_diagnostics(lines, "ProVerif help")
    matches = [
        match.group("version")
        for line in lines
        if (match := _PROVERIF_VERSION_LINE.fullmatch(line)) is not None
    ]
    if not lines or _PROVERIF_VERSION_LINE.fullmatch(lines[0]) is None:
        _fail("ProVerif help does not begin with its version identity")
    if matches != [EXPECTED_PROVERIF_VERSION]:
        _fail("ProVerif help does not contain the one expected version")


def verify_installed(
    selection: ToolSelection,
    *,
    path_environment: str | None = None,
    runner: Runner = capture_output,
) -> tuple[str, ...]:
    """Verify one explicit tool group and return its stable marker names."""

    if selection not in _SELECTION_TO_EXECUTABLES:
        _fail("formal tool selection is invalid")
    selected_path = _path_environment(path_environment)
    executables = _SELECTION_TO_EXECUTABLES[selection]
    if not executables or any(
        name not in _FIXED_EXECUTABLE_NAMES for name in executables
    ):
        _fail("formal tool selection contains a non-fixed executable")

    if "easycrypt" in executables:
        stdout, stderr = _run_identity_command(
            "easycrypt",
            ("config",),
            label="EasyCrypt identity",
            path_environment=selected_path,
            runner=runner,
        )
        _require_empty_stream(stdout, label="EasyCrypt standard output")
        parse_easycrypt_config(stderr)

    if "tamarin-prover" in executables:
        stdout, stderr = _run_identity_command(
            "tamarin-prover",
            ("--version",),
            label="Tamarin identity",
            path_environment=selected_path,
            runner=runner,
        )
        parse_tamarin_version(stdout)
        parse_tamarin_diagnostics(stderr)
        stdout, stderr = _run_identity_command(
            "maude",
            ("--version",),
            label="Maude identity",
            path_environment=selected_path,
            runner=runner,
        )
        _require_empty_stream(stderr, label="Maude standard error")
        parse_maude_version(stdout)

    if "proverif" in executables:
        stdout, stderr = _run_identity_command(
            "proverif",
            ("-help",),
            label="ProVerif identity",
            path_environment=selected_path,
            runner=runner,
        )
        _require_empty_stream(stderr, label="ProVerif standard error")
        parse_proverif_help(stdout)

    return _SELECTION_TO_MARKER_TOOLS[selection]


def _write_line(line: str) -> None:
    payload = f"{line}\n"
    written = sys.stdout.write(payload)
    if written != len(payload):
        raise OSError("could not write the complete formal toolchain result")
    sys.stdout.flush()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify-installed")
    verify.add_argument(
        "--tool",
        choices=tuple(_SELECTION_TO_EXECUTABLES),
        required=True,
    )
    return parser


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        tools = verify_installed(args.tool)
        _write_line(
            "FORMAL_TOOLCHAIN_CONTRACT_PASS tools=" + ",".join(tools)
        )
        return 0
    except (BoundedProcessError, FormalToolchainContractError, OSError) as exc:
        print(f"error: formal toolchain contract: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
