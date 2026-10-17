#!/usr/bin/env python3
"""Run the installed maintenance CLI against a retained real redb-2.6.3 image."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

from evidence_io import parse_strict_json_bytes

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "research/sdk-alpha1/evidence/20261008-storage-format-upgrade"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(not binary.is_relative_to(ROOT), "use an installed executable outside the checkout")
    binary_digest = digest(binary.read_bytes())
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    qualification = parse_strict_json_bytes((EVIDENCE / "QUALIFICATION.json").read_bytes(), label="migration fixture qualification")
    archive = (EVIDENCE / "CAPTURES.zip").read_bytes()
    require(digest(archive) == qualification["captures"]["sha256"], "fixture archive hash differs")
    with zipfile.ZipFile(EVIDENCE / "CAPTURES.zip") as source:
        members = parse_strict_json_bytes(source.read("MEMBERS.json"), label="migration fixture members")
        name = "control-01/original-v2.redb"
        matches = [item for item in members if item["path"] == name]
        require(len(matches) == 1, "legacy fixture identity is ambiguous")
        fixture = source.read(name)
        require(len(fixture) == matches[0]["bytes"] and digest(fixture) == matches[0]["sha256"], "legacy fixture differs")
    require([fixture[64], fixture[192]] == [2, 2], "fixture is not the retained original format 2")
    public = parse_strict_json_bytes((ROOT / "bindings/sdk-policy-recovery-vectors.json").read_bytes(), label="public recovery fixture")
    root_key = bytes.fromhex(public["initial_root"])
    state = bytes.fromhex(public["request"])[112:148]
    require(len(state) == 36, "independent public fixture state differs")
    attempts = []
    with tempfile.TemporaryDirectory(prefix="qperiapt-installed-migration-") as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o700)
        require(not work.is_relative_to(ROOT), "consumer must run outside the checkout")
        path = work / "policy.redb"
        path.write_bytes(fixture)
        path.chmod(0o600)
        inode = path.stat().st_ino
        root = work / "root.bin"
        expected = work / "state.bin"
        root.write_bytes(root_key)
        expected.write_bytes(state)

        def invoke(label: str, target: Path, legacy: bool | None, error_text: str = "") -> None:
            command = [str(binary), "policy-store-upgrade", str(target), "--root", str(root), "--expected-state", str(expected)]
            result = subprocess.run(command, cwd=work, capture_output=True, timeout=30, check=False)
            (output / f"{label}.stdout").write_bytes(result.stdout)
            (output / f"{label}.stderr").write_bytes(result.stderr)
            attempts.append({"case": label, "command": command, "returncode": result.returncode,
                             "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
            if legacy is None:
                require(result.returncode == 1 and not result.stdout, f"{label}: refusal did not fail without a success receipt")
                require(error_text.encode() in result.stderr, f"{label}: wrong refusal")
            else:
                require(result.returncode == 0 and not result.stderr, f"{label}: installed command failed")
                report = parse_strict_json_bytes(result.stdout, label="installed migration observation")
                require(report == {"schema": "q-periapt-policy-store-upgrade/1", "status": "verified-format-3",
                                   "initial_slots": [2, 2] if legacy else [3, 3], "legacy_provider_used": legacy,
                                   "policy_enabled": True, "trusted_state": state.hex()}, f"{label}: observation differs")
                require(target.stat().st_ino == inode, f"{label}: original inode replaced")
                encoded = target.read_bytes()
                require([encoded[64], encoded[192]] == [3, 3], f"{label}: file was not converted")

        invoke("legacy-conversion", path, True)
        invoke("already-current-retry", path, False)
        expected.write_bytes(state + b"\0")
        before = path.read_bytes()
        invoke("oversized-independent-state", path, None, "wrong length")
        require(path.read_bytes() == before, "invalid trust input changed the database")
        expected.write_bytes(state)
        invoke("missing-store", work / "missing.redb", None, "private-file admission")
        require(not (work / "missing.redb").exists(), "missing storage was initialized")
        for offset in (64, 192):
            corrupt = work / f"corrupt-{offset}.redb"
            data = bytearray(path.read_bytes())
            data[offset] = 2
            corrupt.write_bytes(data)
            corrupt.chmod(0o600)
            invoke(f"corrupt-slot-{offset}", corrupt, None, "slot checksum mismatch")
            require(corrupt.read_bytes() == data, "corrupt input was modified")
        invoke("final-current-retry", path, False)
    require(digest(binary.read_bytes()) == binary_digest, "installed executable changed")
    report = {"schema": "q-periapt-policy-store-migration-installed/1", "binary": str(binary),
              "binary_sha256": binary_digest, "fixture_producer": "redb 2.6.3",
              "fixture_sha256": digest(fixture), "attempts": attempts,
              "scope": "Actual installed executable outside checkout; public policy fixture; no Continuity or power-loss claim"}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"POLICY_STORE_MIGRATION_INSTALLED_PASS cases={len(attempts)} binary_sha256={binary_digest}")


if __name__ == "__main__":
    main()
