"""Direct child of the already admitted hardened Python runtime.

The parent retains its empty private cache prefix until every child has exited.
Using the bootstrap directly makes Popen.pid the actual journal owner, so wait()
after SIGKILL waits for that owner's descriptor/lease teardown, not a shell.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import os
import stat
import sys


def command(script: Path, *arguments: str) -> list[str]:
    peer = Path(__file__).resolve().parent
    root = peer.parent.parent
    target = script.resolve(strict=True)
    if not target.is_relative_to(peer) or not target.is_file():
        raise ValueError("worker script outside independent peer")
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is not None):
        raise ValueError("worker requires the admitted hardened parent runtime")
    cache = Path(sys.pycache_prefix)
    current = cache.lstat()
    if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o700 or any(cache.iterdir())):
        raise ValueError("worker cache prefix must remain private and empty")
    return [sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={cache}",
            str(root / "artifact/python_bootstrap.py"), str(target), *arguments]


if __name__ == "__main__":
    import signal
    if sys.argv[1:] != ["--identity-probe"]:
        raise SystemExit("worker probe requires --identity-probe")
    print(os.getpid(), flush=True)
    signal.pause()
    raise RuntimeError("identity probe unexpectedly resumed")
