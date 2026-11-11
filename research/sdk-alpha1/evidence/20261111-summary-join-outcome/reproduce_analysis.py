#!/usr/bin/env python3
"""Relocate frozen readback methods over the two identified workflow archives."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


def verify(path, identity):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    if size != identity["bytes"] or digest.hexdigest() != identity["sha256"]:
        raise ValueError("Byte identity differs: " + str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("semantics", "resources"))
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path)
    args = parser.parse_args()
    packet = Path(__file__).resolve().parent
    archives, output = args.archives.resolve(), args.output.resolve()
    if args.action == "semantics" and args.repository is None:
        parser.error("semantics requires --repository")
    manifest = json.loads((packet / "MANIFEST.json").read_bytes())
    for name, identity in manifest["files"].items():
        verify(packet / name, identity)
    identities = json.loads((packet / "ARTIFACT_IDENTITIES.json").read_bytes())
    for identity in identities:
        verify(archives / (str(identity["id"]) + ".zip"), identity)
    output.mkdir(parents=True, exist_ok=False)

    if args.action == "resources":
        method = packet / "performance/analyze_new.py"
        text = method.read_text()
        replacements = {
            "BASE=Path('/workspace/scratch/4b61438fb07b/summary-performance')": "BASE=Path(" + repr(str(output)) + ")",
            "ZIP=Path('/workspace/scratch/4b61438fb07b/summary-join-readback-42956070561')": "ZIP=Path(" + repr(str(archives)) + ")",
        }
        for old, new in replacements.items():
            if text.count(old) != 1:
                raise ValueError("Frozen method path assignment differs")
            text = text.replace(old, new)
        with tempfile.TemporaryDirectory(prefix="summary-resource-readback-") as temporary:
            script = Path(temporary) / "analyze_new.py"
            script.write_text(text)
            result = subprocess.run([sys.executable, str(script)], check=False)
        return result.returncode

    for identity in identities:
        name = str(identity["id"]) + ".zip"
        shutil.copyfile(archives / name, output / name)
    for name in ("ARTIFACT_IDENTITIES.json", "SOURCE_IDENTITY.json"):
        shutil.copyfile(packet / name, output / name)
    for arm in ("heap-1536", "heap-2048"):
        (output / arm).mkdir()
        shutil.copyfile(packet / arm / "RESULT.json", output / arm / "RESULT.json")
    members = manifest["source_snapshot"]["members"]
    with zipfile.ZipFile(packet / "source-snapshot.zip") as snapshot:
        if set(snapshot.namelist()) != set(members):
            raise ValueError("Source snapshot member census differs")
        (output / "source").mkdir()
        for name, identity in members.items():
            if Path(name).parts != ("source", Path(identity["repository_path"]).name):
                raise ValueError("Source snapshot member path differs")
            data = snapshot.read(name)
            if len(data) != identity["bytes"] or hashlib.sha256(data).hexdigest() != identity["sha256"]:
                raise ValueError("Source snapshot member bytes differ")
            (output / name).write_bytes(data)
    command = [sys.executable, str(packet / "recheck_outcome.py"), "--directory", str(output),
               "--repository", str(args.repository.resolve())]
    first = subprocess.run(command, check=False)
    if first.returncode != 0:
        return first.returncode
    second = subprocess.run([
        sys.executable, str(output / "source/codeql_summary_control.py"), "compare",
        "--baseline", str(output / "heap-2048/RESULT.json"),
        "--candidate", str(output / "heap-1536/RESULT.json"),
        "--summary-plan-mode", "all", "--output", str(output / "LOCAL_COMPARISON.json"),
    ], check=False)
    print("Original full-suite comparator exit status:", second.returncode)
    return second.returncode


if __name__ == "__main__":
    raise SystemExit(main())
