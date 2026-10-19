"""Observe the installed reference in a separate isolated interpreter."""
from pathlib import Path
import hashlib
import importlib
import json
import os
import re
import stat
import sys
from evidence_io import load_json_object_snapshot


def main():
    application, provider, repository, expected, output = map(Path, sys.argv[1:])
    package = application / "qperiapt_continuity_reference"
    required = load_json_object_snapshot(
        expected, maximum=64 * 1024, label="expected installed module hashes"
    ).value
    if (not {"__init__.py", "provider.py"} <= required.keys()
            or any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", name) is None
                   or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                   for name, digest in required.items())):
        raise ValueError("expected installed module hashes have an invalid schema")
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is not None):
        raise ValueError("installed probe requires isolated, no-site, no-bytecode execution")
    cache = Path(sys.pycache_prefix)
    info = cache.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or any(cache.iterdir())):
        raise ValueError("installed probe cache is not private and empty")
    sys.path.append(str(application))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(provider)
    loaded = {}
    for filename in sorted(required):
        name = "qperiapt_continuity_reference" + ("" if filename == "__init__.py" else "." + Path(filename).stem)
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve(strict=True)
        if path != package / filename:
            raise ValueError("reference module loaded outside installation")
        loaded[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    if (loaded != required or any(Path(path).resolve().is_relative_to(repository) for path in sys.path)
            or any(name == "peer" or name.startswith("peer.") for name in sys.modules)
            or any(cache.iterdir())):
        raise ValueError("installed source, import path or cache admission differs")
    output.write_text(json.dumps({"modules": loaded, "package_root": str(package), "sys_path": sys.path,
        "python": sys.version, "isolated": sys.flags.isolated, "no_site": sys.flags.no_site,
        "dont_write_bytecode": sys.flags.dont_write_bytecode, "pycache_prefix": sys.pycache_prefix,
        "cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}, indent=2) + "\n")


if __name__ == "__main__":
    main()
