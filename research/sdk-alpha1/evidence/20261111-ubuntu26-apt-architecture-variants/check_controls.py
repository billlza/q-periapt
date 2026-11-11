"""Exercise the exact helper body with isolated host/tool-location fixtures.

Only OS-release/keyring/tool locations and the deadline duration are replaced;
no production source is edited and no real apt or sudo operation is executed.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parent / "apt-variants-fix/artifact/ci_apt.sh"
source = SOURCE.read_text()
records = []
with tempfile.TemporaryDirectory(prefix="qperiapt-apt-controls-") as temporary:
    root = Path(temporary)
    bins = root / "bin"
    bins.mkdir()
    os_release = root / "os-release"
    keyring = root / "keyring.gpg"
    keyring.write_bytes(b"fixture: trust is exercised by the hosted APT run")
    sudo = bins / "sudo"
    sudo.write_text('#!/bin/bash\nif [ "$1" = -n ]; then shift; fi\nexec "$@"\n')
    dpkg = bins / "dpkg"
    dpkg.write_text('#!/bin/bash\nprintf "%s\\n" "$CONTROL_ARCH"\n')
    apt = bins / "apt-get"
    apt.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys, time
arguments = sys.argv[1:]
options = dict(arguments[i+1].split("=", 1) for i, a in enumerate(arguments) if a == "-o")
stage = "update" if arguments[-1] == "update" else "install"
source = pathlib.Path(options["Dir::Etc::sourcelist"])
with open(os.environ["CONTROL_TRACE"], "a") as stream:
    stream.write(json.dumps({"stage": stage, "argv": arguments, "options": options,
                             "sources": source.read_text(), "directory": str(source.parent)}) + "\\n")
if os.environ.get("CONTROL_HANG") == stage:
    time.sleep(10)
sys.exit(100 if os.environ.get("CONTROL_FAIL") == stage else 0)
''')
    for program in (sudo, dpkg, apt):
        program.chmod(0o755)
    instrumented = source.replace('. /etc/os-release', f'. "{os_release}"')
    instrumented = instrumented.replace('keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg',
                                        f'keyring="{keyring}"')
    instrumented = instrumented.replace('/usr/bin/apt-get', str(apt))
    cases = [
        ("noble-amd64", "noble", "amd64", "", "", ["qemu-user", "gcc-riscv64-linux-gnu"], 0, ["update", "install"]),
        ("jammy-amd64", "jammy", "amd64", "", "", ["valgrind"], 0, ["update", "install"]),
        ("resolute-amd64", "resolute", "amd64", "", "", ["valgrind"], 0, ["update", "install"]),
        ("resolute-amd64v3", "resolute", "amd64v3", "", "", ["valgrind"], 0, ["update", "install"]),
        ("noble-arm64", "noble", "arm64", "", "", ["valgrind"], 0, ["update", "install"]),
        ("unsupported-suite", "unverified", "amd64", "", "", ["valgrind"], 2, []),
        ("unsupported-architecture", "jammy", "arm64", "", "", ["valgrind"], 2, []),
        ("no-packages", "noble", "amd64", "", "", [], 1, []),
        ("options-rejected", "noble", "amd64", "", "", ["--allow-unauthenticated"], 2, []),
        ("update-fails", "noble", "amd64", "update", "", ["valgrind"], 100, ["update"]),
        ("install-fails", "noble", "amd64", "install", "", ["valgrind"], 100, ["update", "install"]),
        ("update-deadline", "noble", "amd64", "", "update", ["valgrind"], 124, ["update"]),
        ("install-deadline", "noble", "amd64", "", "install", ["valgrind"], 124, ["update", "install"]),
    ]
    for name, suite, architecture, fail, hang, packages, status, stages in cases:
        os_release.write_text(f'ID=ubuntu\nVERSION_CODENAME={suite}\n')
        trace = root / f"{name}.jsonl"
        script = root / f"{name}.sh"
        script.write_text(instrumented.replace("360s", "0.3s").replace("--kill-after=10s", "--kill-after=0.2s")
                          if hang else instrumented)
        environment = dict(os.environ, PATH=f"{bins}:/usr/bin:/bin", CONTROL_ARCH=architecture,
                           CONTROL_FAIL=fail, CONTROL_HANG=hang, CONTROL_TRACE=str(trace))
        started = time.monotonic()
        result = subprocess.run(["/bin/bash", str(script), *packages], env=environment,
                                capture_output=True, text=True, timeout=5)
        elapsed = time.monotonic() - started
        observed = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        assert result.returncode == status, (name, result.returncode, result.stderr)
        assert [item["stage"] for item in observed] == stages, (name, observed)
        if observed:
            first = observed[0]
            options = first["options"]
            assert "Dir::State" not in options
            assert options["APT::Update::Error-Mode"] == "any"
            assert options["Acquire::Check-Date"] == options["Acquire::Check-Valid-Until"] == "true"
            assert options["APT::Get::AllowUnauthenticated"] == "false"
            assert len(first["sources"].splitlines()) == 4
            mirror = "https://mirrors.ocf.berkeley.edu/ubuntu-ports" if architecture == "arm64" else "https://mirrors.edge.kernel.org/ubuntu"
            assert all(mirror in line and "arch=" not in line and f"signed-by={keyring}" in line
                       for line in first["sources"].splitlines())
            if len(observed) == 2:
                assert observed[1]["options"] == options
                assert observed[1]["sources"] == first["sources"]
                assert observed[1]["argv"][-len(packages):] == packages
            assert not Path(first["directory"]).exists(), "private APT directory leaked"
        if hang:
            assert elapsed < 2, (name, elapsed)
        records.append({"case": name, "status": result.returncode, "stages": stages,
                        "elapsed_seconds": elapsed, "stdout": result.stdout, "stderr": result.stderr})

report = {"helper_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
          "scope": "host/tool-location fixtures; no actual APT trust or package installation",
          "passed": len(records), "records": records}
(ROOT / "CONTROLS.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"passed": len(records), "helper_sha256": report["helper_sha256"]}))
