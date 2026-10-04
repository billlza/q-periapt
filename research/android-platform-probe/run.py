"""Supervise private hosted Android service and transport experiments."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import argparse

from bounded_process import BoundedProcessError, capture_stdout
from android_apk_transport_probe import MODES, UNINSTALLED_MODES, prepare_archive

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "target/android-platform-probe"


def main(experiment: str = "file-integrity") -> int:
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
    if experiment not in ("file-integrity", *MODES):
        raise ValueError("unknown platform experiment")
    output = OUTPUT if experiment == "file-integrity" else ROOT / "target/android-apk-transport-probe"
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True)
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "JAVA_HOME")}
    environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "QPERIAPT_PYTHON": sys.executable,
                        "GITHUB_ACTIONS": "true"})
    timeout = 360 if experiment == "file-integrity" else 600
    record = {"kind": "qperiapt.android_platform_reproduction", "schema_version": 1,
              "source_commit": commit, "sdk_installation_attempted": False,
              "routing": "private_unix_adb_with_emulator_registration",
              "status": "not_completed",
              "release_claim_eligible": False, "timeout_seconds": timeout,
              "output_limit_bytes": 2 * 1024 * 1024,
              "scope": "one cold API 35 / 16 KiB boot and read-only file_integrity queries; no SDK qualification"}
    status = 1
    try:
        if experiment != "file-integrity":
            record.update(experiment=experiment, sdk_installation_requested=experiment not in UNINSTALLED_MODES,
                scope="fixed historical bytes on a cold API35/16KiB image; installed APK or uninstalled ordinary-file bulk copy; finite diagnostic, not SDK qualification",
                apk_source=prepare_archive(ROOT / "target/android-apk-probe-intake", output / "probe.apk"))
        with (output / "commands.log").open("xb") as log:
            result = capture_stdout(
                ["/bin/bash", str(ROOT / "research/android-platform-probe/run.sh"), experiment],
                timeout_seconds=timeout, maximum_bytes=2 * 1024 * 1024,
                stderr=subprocess.STDOUT, environment=environment, output_sink=log.write)
        if experiment in UNINSTALLED_MODES and b"APK_TRANSPORT_INSTALL_ATTEMPT\n" in (output / "commands.log").read_bytes():
            raise RuntimeError("uninstalled transport experiment attempted package installation")
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
        log = output / "commands.log"
        if log.exists():
            record["commands_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
            if experiment != "file-integrity":
                record["sdk_installation_attempted"] = b"APK_TRANSPORT_INSTALL_ATTEMPT\n" in log.read_bytes()
                record["uninstalled_blob_staging_attempted"] = b"APK_TRANSPORT_BLOB_STAGE\n" in log.read_bytes()
        with (output / "observation.json").open("x") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return 0 if status == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", choices=("file-integrity", *MODES), default="file-integrity")
    raise SystemExit(main(parser.parse_args().experiment))
