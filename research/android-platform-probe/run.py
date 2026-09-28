"""Supervise a hosted, SDK-free Android system-service reproduction."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from bounded_process import BoundedProcessError, capture_stdout

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "target/android-platform-probe"


def main() -> int:
    # This diagnostic is intentionally unavailable on a developer's machine.
    # The workflow creates a disposable hosted Linux runner and grants KVM.
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "Linux"
            or sys.platform != "linux"):
        raise RuntimeError("platform reproduction requires its hosted Linux workflow")
    commit = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RuntimeError("platform reproduction lacks the selected source commit")
    observed = capture_stdout(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"],
                              timeout_seconds=5, maximum_bytes=128)
    if observed.returncode != 0 or observed.stdout.decode().strip() != commit:
        raise RuntimeError("platform reproduction source differs")
    clean = capture_stdout(["/usr/bin/git", "-C", str(ROOT), "diff", "--quiet", "HEAD"],
                           timeout_seconds=5, maximum_bytes=1024)
    if clean.returncode != 0:
        raise RuntimeError("platform reproduction requires unchanged tracked sources")
    os.umask(0o077)
    OUTPUT.mkdir(mode=0o700, parents=True)
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "JAVA_HOME")}
    environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    record = {"kind": "qperiapt.android_platform_reproduction", "schema_version": 1,
              "source_commit": commit, "sdk_installation_attempted": False,
              "status": "not_completed",
              "release_claim_eligible": False, "timeout_seconds": 360,
              "output_limit_bytes": 2 * 1024 * 1024,
              "scope": "one cold API 35 / 16 KiB boot and read-only file_integrity queries; no SDK qualification"}
    status = 1
    try:
        with (OUTPUT / "commands.log").open("xb") as log:
            result = capture_stdout(
                ["/bin/bash", str(ROOT / "research/android-platform-probe/run.sh")],
                timeout_seconds=360, maximum_bytes=2 * 1024 * 1024,
                stderr=subprocess.STDOUT, environment=environment, output_sink=log.write)
        status = result.returncode
        record.update(status="observations_completed" if status == 0 else "observation_failed",
                      driver_exit_status=status)
    except BoundedProcessError as error:
        record.update(status="supervisor_failed", failure_kind=error.kind, failure=str(error))
        raise
    except BaseException as error:
        record.update(status="supervisor_failed", failure_type=type(error).__name__)
        raise
    finally:
        log = OUTPUT / "commands.log"
        if log.exists():
            record["commands_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        with (OUTPUT / "observation.json").open("x") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return 0 if status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
