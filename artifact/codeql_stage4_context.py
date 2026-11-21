"""Give the tracked stage-4 modules their pinned, fully patched Cargo owners."""
from __future__ import annotations

import contextlib
import json
from pathlib import Path
import re
import sys

from codeql_consumer_context import CANDIDATE, identity
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk


STUDY = Path("research/continuity-persistence-030/stage4")
OVERLAY = STUDY / "overlay"
LIB = Path("src/lib.rs")
TEST = Path("tests/owned_connection.rs")


def materialize(run, compiler: str) -> Path:
    work = run.output / "stage4-inputs"
    run.command("stage4-prepare", [sys.executable, "-I", "-S", "-B",
                                   str(run.root / STUDY / "run.py"), "prepare", str(work)])
    pkg = work / "prototype" / CANDIDATE
    run.command("stage4-fetch", ["cargo", "+" + compiler, "fetch", "--locked",
                                 "--manifest-path", str(pkg / "Cargo.toml")])
    return pkg


def replace_once(text: str, old: str, new: str) -> str:
    sdk.require(text.count(old) == 1, "pinned stage-4 Cargo or module declaration differs")
    return text.replace(old, new)


@contextlib.contextmanager
def cargo_context(root: Path, pkg: Path):
    """Compile the original tracked paths; only the disposable parents are redirected."""
    overlay = root / OVERLAY
    sdk.require(not pkg.is_relative_to(root), "stage-4 support sources must be outside the index")
    lock = parse_strict_json_bytes(sdk.snapshot(root / STUDY / "source-lock.json").data, label="stage-4 source lock")
    expected = lock["added"]
    sdk.require(set(expected) == {p.relative_to(overlay).as_posix() for p in overlay.rglob("*.rs")},
                "stage-4 overlay source inventory differs")
    for name, digest in expected.items():
        sdk.require(sdk.snapshot(overlay / name).sha256 == sdk.snapshot(pkg / name).sha256 == digest,
                    "stage-4 overlay source bytes differ")
    for parent, source, old in (
        ("src/durable/messages/rekey/response.rs", "src/durable/messages/rekey/response/stage4.rs", "mod stage4;"),
        ("src/durable/messages/tests.rs", "src/durable/messages/tests/stage4_matched.rs", "mod stage4_matched;"),
        (str(TEST), "tests/owned_connection/stage4.rs", '#[path = "owned_connection/stage4.rs"]'),
    ):
        path = pkg / parent
        original = sdk.snapshot(path)
        sdk.require(original.sha256 == lock["modified"][parent]["prototype"], "stage-4 parent differs")
        attribute = "#[path = " + json.dumps(str(overlay / source)) + "]"
        new = attribute + "\n" + old if old.startswith("mod ") else attribute
        path.write_text(replace_once(original.data.decode(), old, new))

    manifest = sdk.snapshot(pkg / "Cargo.toml")
    sdk.require(manifest.sha256 == lock["modified"]["Cargo.toml"]["prototype"], "stage-4 manifest differs")
    text = re.sub(r'path = "(\.\./\.\./crates/[\w-]+)"',
                  lambda m: "path = " + json.dumps(str((pkg / m[1]).resolve(strict=True))),
                  manifest.data.decode())
    text = replace_once(text, "[lib]", "[lib]\npath = " + json.dumps(str(pkg / LIB)))
    text += '\n[[test]]\nname = "owned_connection"\npath = ' + json.dumps(str(pkg / TEST)) + "\n"
    lockfile = sdk.snapshot(pkg / "Cargo.lock")
    sdk.require(lockfile.sha256 == lock["engine_lock_sha256"], "stage-4 Cargo.lock differs")
    owned = {}
    try:
        for name, data in (("Cargo.toml", text.encode()), ("Cargo.lock", lockfile.data)):
            path = overlay / name
            with path.open("xb") as stream:
                stream.write(data)
            owned[path] = identity(path)
        yield {pkg / rel: sdk.snapshot(pkg / rel).sha256 for rel in (LIB, TEST)}
    finally:
        for path, original in owned.items():
            sdk.require(identity(path) == original, "stage-4 analysis manifest or lock changed")
        for path in owned:
            path.unlink()


def require_compiled(profile: str, source: dict, compiled: dict) -> None:
    if profile in ("native", "macos"):
        paths = {p for p in source if p.startswith(OVERLAY.as_posix() + "/")}
        sdk.require(paths <= compiled.keys(), "compiler evidence omits a tracked stage-4 module")
