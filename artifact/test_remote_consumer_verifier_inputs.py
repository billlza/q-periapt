#!/usr/bin/env python3
"""Guard: the remote-consumer's VERIFIER_INPUTS must cover the full repo-local
import closure of every Python entry point it runs in the isolated snapshot.

The Swift remote-consumer materializes only the fixed ``VERIFIER_INPUTS`` list
into an isolated snapshot and runs ``apple_stable_publication.py`` there with a
cleared environment (``python_bootstrap`` resolves imports only from the
snapshot). If that module gains a transitive import that is not listed, the gate
fails at load time with ``ModuleNotFoundError`` for every draft-based release.
This test recomputes the closure from source so the list cannot silently drift.
"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest


ARTIFACT_DIR = pathlib.Path(__file__).resolve().parent
REMOTE_CONSUMER_SCRIPT = ARTIFACT_DIR / "swift-xcframework-remote-consumer.sh"

# Python entry points the remote-consumer script executes from the snapshot.
GATE_ENTRY_POINTS = ("apple_stable_publication",)


def _local_module_names() -> set[str]:
    return {path.stem for path in ARTIFACT_DIR.glob("*.py")}


def _repo_local_imports(module: str, local_mods: set[str]) -> set[str]:
    source = (ARTIFACT_DIR / f"{module}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in local_mods:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in local_mods:
                    found.add(alias.name)
    return found


def _import_closure(entry_points: tuple[str, ...]) -> set[str]:
    local_mods = _local_module_names()
    seen: set[str] = set()
    stack = list(entry_points)
    while stack:
        module = stack.pop()
        if module in seen:
            continue
        seen.add(module)
        stack.extend(_repo_local_imports(module, local_mods) - seen)
    return seen


def _parse_verifier_inputs() -> list[str]:
    text = REMOTE_CONSUMER_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"VERIFIER_INPUTS='([^']*)'", text)
    if match is None:
        raise AssertionError("VERIFIER_INPUTS assignment not found in the script")
    return [line for line in match.group(1).splitlines() if line]


class RemoteConsumerVerifierInputsTests(unittest.TestCase):
    def test_verifier_inputs_cover_gate_import_closure(self) -> None:
        verifier_py = {
            pathlib.PurePosixPath(entry).stem
            for entry in _parse_verifier_inputs()
            if entry.endswith(".py")
        }
        closure = _import_closure(GATE_ENTRY_POINTS)
        missing = sorted(closure - verifier_py)
        self.assertEqual(
            [],
            missing,
            "VERIFIER_INPUTS omits Python modules the gate imports at load time: "
            + ", ".join(missing),
        )

    def test_verifier_inputs_entries_exist_and_are_unique(self) -> None:
        entries = _parse_verifier_inputs()
        self.assertEqual(len(entries), len(set(entries)), "duplicate VERIFIER_INPUTS entry")
        repo_root = ARTIFACT_DIR.parent
        for entry in entries:
            self.assertTrue(
                (repo_root / entry).is_file(),
                f"VERIFIER_INPUTS entry does not exist: {entry}",
            )


if __name__ == "__main__":
    unittest.main()
