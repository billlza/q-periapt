"""Test-only loading of a committed reference writer and its complete peer code."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import zipfile


def version_two(private):
    from peer.wire import require
    archive = Path("research/sdk-alpha1/evidence/20261018-independent-durable-rekey/CAPTURE.zip")
    checks = json.loads(archive.with_name("CHECKS.json").read_text())
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == checks["capture"]["sha256"],
            "archived peer capture changed")
    destination = private / "archived-peer"
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as saved:
        for name, expected in checks["source_files"].items():
            if not name.startswith("peer/") or not name.endswith(".py"):
                continue
            require(Path(name).parent == Path("peer"), "archived peer source path")
            data = saved.read("source/" + name)
            require(hashlib.sha256(data).hexdigest() == expected, "archived peer source changed")
            (destination / Path(name).name).write_bytes(data)
    name = "archived_peer_" + hashlib.sha256(str(private).encode()).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(name, destination / "__init__.py",
                                                submodule_search_locations=[str(destination)])
    require(spec is not None and spec.loader is not None, "archived package loader")
    package = importlib.util.module_from_spec(spec)
    sys.modules[name] = package
    spec.loader.exec_module(package)
    return importlib.import_module(name + ".state_codec"), checks["source_files"]["peer/state_codec.py"]
