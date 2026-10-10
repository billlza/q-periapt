#!/usr/bin/env python3
"""Bounded, no-SDK-workload control on a disposable GitHub-hosted Linux runner.

This is an experiment, not an Android SDK qualification gate. It keeps every
failed observation, never installs an APK, and stops only its own child processes.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import tempfile
import time

import bounded_process


IMAGE = "system-images;android-35;google_apis_ps16k;x86_64"
AVD = "QPeriapt_Runtime_Control_API35"
SERIAL = "emulator-5554"
GUEST_FILE = "/apex/com.android.art/lib64/libart.so"
FINGERPRINT = "google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys"
IMAGE_HASHES = {
    "kernel-ranchu": "987818a35792fb62f6ea6aa604d5fa476e1e85c84fc1cbac3979e1ae26965f46",
    "ramdisk.img": "815828912f1ad2652e683a8b81487bebb64d2620d05a8b84e2c6dc2f9a743a90",
    "source.properties": "ed5a16eb74b8bc0e58c938eb9d3159a986855e3aebbd53f79a3273962630f663",
    "system.img": "5c5dabeee5c63652e485947e62f2849f4ae3fba5d425eeba9df24c3f1e5f042c",
}


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def transfer_matches(record: dict, expected_size: int, expected_hash: str) -> bool:
    return (
        record["returncode"] == 0
        and not record["timed_out"]
        and not record.get("bounded_failure")
        and record["stdout_bytes"] == expected_size
        and record["stdout_sha256"] == expected_hash
    )


class Control:
    def __init__(self, output: Path, sdk: Path, avdmanager: Path):
        output.mkdir(mode=0o700)
        self.output = output
        self.sdk = sdk
        self.avdmanager = avdmanager
        self.work = Path(tempfile.mkdtemp(prefix="qpc-android-control-"))
        self.children: list[tuple[str, subprocess.Popen]] = []
        self.deadline = time.monotonic() + 900
        self.environment = dict(os.environ)
        for name in ("ANDROID_ADB_SERVER_PORT", "ANDROID_ADB_SERVER_ADDRESS", "ANDROID_SERIAL", "ADB_TRACE"):
            self.environment.pop(name, None)
        self.environment.update({
            "ANDROID_AVD_HOME": str(self.work / "avd"),
            "ANDROID_USER_HOME": str(self.work / "android"),
            "ADB_SERVER_SOCKET": "localfilesystem:" + str(self.work / "adb.sock"),
            "ADB_VENDOR_KEYS": str(self.work / "android" / "adbkey"),
            "ADB_USB": "0", "ADB_EMU": "0", "ADB_MDNS": "0",
            "ADB_MDNS_AUTO_CONNECT": "0",
        })
        for key in ("ANDROID_AVD_HOME", "ANDROID_USER_HOME"):
            Path(self.environment[key]).mkdir(mode=0o700)
        self.adb = sdk / "platform-tools/adb"
        self.emulator = sdk / "emulator/emulator"
        self.events: list[dict] = []
        self.samples: list[dict] = []
        self.result: dict = {
            "kind": "qperiapt.android_no_sdk_workload_control", "schema": 1,
            "source_commit": os.environ["GITHUB_SHA"],
            "run_id": os.environ["GITHUB_RUN_ID"],
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "controller_sha256": file_hash(Path(__file__)),
            "bounded_writer_sha256": file_hash(Path(bounded_process.__file__)),
            "host": {"architecture": platform.machine(), "kernel": platform.release(),
                     "cpu_count": os.cpu_count(), "python": platform.python_version()},
            "sdk_workload_executed": False, "release_claim_eligible": False,
            "completed": False, "samples": self.samples, "commands": self.events,
            "scope": "One fresh x86_64 ps16k emulator; no APK install or SDK execution. File-copy observations compare direct stdout-to-file with the production bounded stdout writer. They do not reproduce the complete installed-APK/cleanup harness or exonerate the SDK workload.",
        }

    def command(self, label: str, argv: list[str], timeout: int = 20,
                input_bytes: bytes | None = None) -> dict:
        started = time.monotonic()
        started_utc = datetime.now(timezone.utc).isoformat()
        remaining = self.deadline - started
        if remaining <= 0:
            raise RuntimeError("control observation exceeded its 15-minute deadline")
        effective_timeout = min(timeout, remaining)
        with (self.output / (label + ".stdout")).open("xb") as stdout, \
             (self.output / (label + ".stderr")).open("xb") as stderr:
            try:
                child = subprocess.run(argv, input=input_bytes, stdout=stdout,
                                       stderr=stderr, env=self.environment, timeout=effective_timeout)
                code, timed_out = child.returncode, False
            except subprocess.TimeoutExpired:
                code, timed_out = None, True
        out = self.output / (label + ".stdout")
        error = self.output / (label + ".stderr")
        record = {"label": label, "argv": argv, "returncode": code,
                  "capture_method": "direct-file",
                  "started_utc": started_utc,
                  "timed_out": timed_out, "seconds": time.monotonic() - started,
                  "stdout_bytes": out.stat().st_size, "stdout_sha256": file_hash(out),
                  "stderr_bytes": error.stat().st_size, "stderr_sha256": file_hash(error)}
        self.events.append(record)
        self.save()
        return record

    def bounded_command(self, label: str, argv: list[str], maximum: int,
                        timeout: int = 30) -> dict:
        """Use the same stdout engine and exact-size bound as APK readback."""
        started = time.monotonic()
        started_utc = datetime.now(timezone.utc).isoformat()
        remaining = int(self.deadline - started)
        if remaining < 1:
            raise RuntimeError("control observation exceeded its 15-minute deadline")
        effective_timeout = min(timeout, remaining)
        directory_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        code = None
        primary: BaseException | None = None
        try:
            with (self.output / (label + ".stderr")).open("xb") as stderr:
                result = bounded_process.write_stdout_at(
                    argv, output_directory_fd=directory_fd,
                    output_name=label + ".stdout", timeout_seconds=effective_timeout,
                    maximum_bytes=maximum, stderr=stderr.fileno(),
                    environment=self.environment, retain_nonzero=False,
                )
                code = result.returncode
        except BaseException as error:
            primary = error
        finally:
            try:
                os.close(directory_fd)
            except OSError as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note(f"closing the control output directory also failed: {error}")
            try:
                output = self.output / (label + ".stdout")
                error_output = self.output / (label + ".stderr")
                failure = None if primary is None else {
                    "kind": primary.kind if isinstance(primary, bounded_process.BoundedProcessError) else type(primary).__name__,
                    "message": str(primary), "notes": list(getattr(primary, "__notes__", ()))}
                # Production does not publish timed-out, overflowing or nonzero
                # output. Preserve that absence instead of inventing empty bytes.
                record = {"label": label, "argv": argv, "capture_method": "bounded-writer",
                          "started_utc": started_utc, "seconds": time.monotonic() - started,
                          "timeout_seconds": effective_timeout, "maximum_bytes": maximum,
                          "returncode": code, "timed_out": failure is not None and failure["kind"] == "timeout",
                          "bounded_failure": failure, "stdout_published": output.is_file(),
                          "stdout_bytes": output.stat().st_size if output.is_file() else None,
                          "stdout_sha256": file_hash(output) if output.is_file() else None,
                          "stderr_bytes": error_output.stat().st_size if error_output.is_file() else None,
                          "stderr_sha256": file_hash(error_output) if error_output.is_file() else None}
                self.events.append(record)
                self.save()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note(f"retaining the failed control observation also failed: {error}")
        if primary is not None:
            raise primary
        return record

    def save(self):
        temporary = self.output / "RESULT.json.new"
        temporary.write_text(json.dumps(self.result, indent=2) + "\n")
        temporary.replace(self.output / "RESULT.json")

    def text(self, record: dict) -> str:
        if record["returncode"] != 0 or record["timed_out"]:
            raise RuntimeError("command failed: " + record["label"])
        if record["stdout_bytes"] > 1024 * 1024:
            raise RuntimeError("unexpectedly large command text: " + record["label"])
        return (self.output / (record["label"] + ".stdout")).read_text().strip()

    def spawn(self, label: str, argv: list[str], environment: dict | None = None):
        with (self.output / (label + ".log")).open("xb") as log:
            child = subprocess.Popen(argv, env=self.environment if environment is None else environment,
                                     stdout=log, stderr=subprocess.STDOUT)
        self.children.append((label, child))
        return child

    def adb_command(self, label: str, args: list[str], timeout: int = 15) -> dict:
        for name, child in self.children:
            if child.poll() is not None:
                raise RuntimeError("owned process exited: " + name)
        return self.command(label, [str(self.adb), "-s", SERIAL, *args], timeout)

    def adb_bounded_command(self, label: str, args: list[str], maximum: int) -> dict:
        for name, child in self.children:
            if child.poll() is not None:
                raise RuntimeError("owned process exited: " + name)
        return self.bounded_command(label, [str(self.adb), "-s", SERIAL, *args], maximum)

    def snapshot(self, label: str):
        probes = {
            "meminfo": ["cat", "/proc/meminfo"],
            "zoneinfo": ["cat", "/proc/zoneinfo"],
            "vmstat": ["cat", "/proc/vmstat"],
            "system-server": ["pidof", "system_server"],
            "adbd": ["pidof", "adbd"],
            "adbd-service": ["getprop", "init.svc.adbd"],
            "boot-id": ["cat", "/proc/sys/kernel/random/boot_id"],
            "uptime": ["cat", "/proc/uptime"],
            "logcat": ["logcat", "-d", "-t", "2000", "-b", "all", "-v", "threadtime",
                       "lmkd:*", "lowmemorykiller:*", "adbd:*", "init:*", "libc:F", "DEBUG:*",
                       "AndroidRuntime:E", "ActivityManager:I", "*:S"],
        }
        for name, args in probes.items():
            record = self.adb_command(label + "-" + name, ["shell", *args])
            if record["returncode"] != 0 or record["timed_out"]:
                self.result.setdefault("diagnostic_failures", []).append(record["label"])

    def run(self):
        image_dir = self.sdk / "system-images/android-35/google_apis_ps16k/x86_64"
        identity = {name: file_hash(image_dir / name) for name in IMAGE_HASHES}
        self.result["system_image_sha256"] = identity
        if identity != IMAGE_HASHES:
            raise RuntimeError("installed system image differs from the failed 8b8d6320 run")
        version = self.text(self.command("emulator-version", [str(self.emulator), "-no-window", "-version"]))
        if "Android emulator version 37.2.12.0" not in version:
            raise RuntimeError("emulator version differs from the failed run")
        self.result["tools"] = {"adb": file_hash(self.adb), "emulator": file_hash(self.emulator)}
        self.text(self.command("create-avd", [str(self.avdmanager), "create", "avd",
                  "--name", AVD, "--package", IMAGE, "--device", "pixel_6"], 60, b"no\n"))
        config = Path(self.environment["ANDROID_AVD_HOME"]) / (AVD + ".avd/config.ini")
        (self.output / "avd-config.ini").write_bytes(config.read_bytes())
        self.text(self.command("adb-keygen", [str(self.adb), "keygen", self.environment["ADB_VENDOR_KEYS"]]))
        os.chmod(self.environment["ADB_VENDOR_KEYS"], 0o600)
        # New private Unix socket; no existing server, USB device or port scan.
        server = self.spawn("adb-server", [str(self.adb), "-L", self.environment["ADB_SERVER_SOCKET"], "server", "nodaemon"])
        socket_path = self.work / "adb.sock"
        deadline = time.monotonic() + 15
        while not socket_path.is_socket():
            if server.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("owned private adb server did not start")
            time.sleep(0.1)
        for port in (5554, 5555, 5586):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        # Keep both guest consoles independent of ADB. With VirtconsoleLogcat,
        # logcat and the kernel cannot both own QEMU's stdio character device.
        self.result["guest_kernel_console"] = "emulator.log"
        self.result["guest_logcat_console"] = "guest-logcat.log"
        self.spawn("emulator", [str(self.emulator), "-avd", AVD, "-port", "5554",
                   "-no-snapshot", "-read-only", "-no-window", "-no-audio",
                   "-no-boot-anim", "-show-kernel", "-no-direct-adb", "-adb-path", str(self.adb),
                   "-logcat", "lmkd:V lowmemorykiller:V adbd:V init:I libc:F DEBUG:V AndroidRuntime:E ActivityManager:I *:S",
                   "-logcat-output", str(self.output / "guest-logcat.log"),
                   "-gpu", "swiftshader"],
                   {**self.environment, "ANDROID_ADB_SERVER_PORT": "5586"})
        deadline = time.monotonic() + 90
        for attempt in range(90):
            if any(child.poll() is not None for _, child in self.children):
                raise RuntimeError("owned process exited before registration")
            record = self.command(f"register-{attempt:02}", [str(self.adb), "connect", "emu:5554,5555"], 5)
            if record["returncode"] == 0 and not record["timed_out"]:
                answer = self.text(record)
                if answer in ("Connected to emulator on ports 5554,5555", "Emulator already registered on port 5555"):
                    break
            if time.monotonic() >= deadline:
                raise RuntimeError("emulator registration deadline")
            time.sleep(1)
        else:
            raise RuntimeError("emulator registration attempt limit")
        deadline = time.monotonic() + 240
        for attempt in range(120):
            record = self.adb_command(f"boot-{attempt:03}", ["shell", "getprop", "sys.boot_completed"], 5)
            if record["returncode"] == 0 and not record["timed_out"] and self.text(record) == "1":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("cold boot deadline")
            time.sleep(2)
        else:
            raise RuntimeError("cold boot attempt limit")
        fingerprint = self.text(self.adb_command("fingerprint", ["shell", "getprop", "ro.build.fingerprint"]))
        page_size = self.text(self.adb_command("page-size", ["shell", "getconf", "PAGE_SIZE"]))
        if fingerprint != FINGERPRINT or page_size != "16384":
            raise RuntimeError("running image or page size differs")
        self.result.update(fingerprint=fingerprint, runtime_page_size=int(page_size))
        self.result["boot_observed_monotonic"] = time.monotonic()
        self.result["boot_observed_utc"] = datetime.now(timezone.utc).isoformat()
        self.save()
        self.observe()

    def observe(self):
        # Guest hashes bracket each transfer; successful exit alone is insufficient.
        size_text = self.text(self.adb_command("file-size", ["shell", "stat", "-c", "%s", GUEST_FILE]))
        if not size_text.isdecimal() or not 1024 * 1024 <= int(size_text) <= 64 * 1024 * 1024:
            raise RuntimeError("unexpected read-only system file size")
        expected_size = int(size_text)
        baseline_hash = self.guest_hash("file-hash")
        self.result.update(guest_file=GUEST_FILE, guest_file_size=expected_size, guest_file_sha256=baseline_hash)
        initial_pid = self.text(self.adb_command("system-server-initial", ["shell", "pidof", "system_server"]))
        if re.fullmatch(r"[1-9][0-9]*", initial_pid) is None:
            raise RuntimeError("system_server identity unavailable")
        self.result["copy_capture_methods"] = ["direct-file", "bounded-writer"]
        self.result["samples_per_capture_method"] = 12
        for sample in range(12):
            label = f"sample-{sample:02}"
            self.snapshot(label)
            methods = ("direct-file", "bounded-writer")
            if sample % 2:
                methods = tuple(reversed(methods))
            for method in methods:
                capture = label + "-" + method
                before = self.guest_hash(capture + "-hash-before")
                if method == "direct-file":
                    transfer = self.adb_command(capture + "-transfer", ["exec-out", "cat", GUEST_FILE], 30)
                else:
                    transfer = self.adb_bounded_command(capture + "-transfer",
                        ["exec-out", "cat", GUEST_FILE], expected_size)
                after = self.guest_hash(capture + "-hash-after")
                pid = self.text(self.adb_command(capture + "-pid-after", ["shell", "pidof", "system_server"]))
                self.samples.append({"sample": sample, "capture_method": method,
                                     "transfer": transfer["label"],
                                     "exact_transfer": transfer_matches(transfer, expected_size, baseline_hash),
                                     "guest_hash_unchanged": before == baseline_hash == after,
                                     "system_server_pid": pid, "original_system_server": pid == initial_pid})
                self.save()
            if sample < 11:
                time.sleep(30)
        self.snapshot("final")
        self.result["completed"] = True
        self.result["observations_clean"] = not self.result.get("diagnostic_failures") and all(
            row["exact_transfer"] and row["guest_hash_unchanged"] and row["original_system_server"]
            for row in self.samples)

    def guest_hash(self, label: str) -> str:
        value = self.text(self.adb_command(label, ["shell", "sha256sum", GUEST_FILE]))
        match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(GUEST_FILE), value)
        if match is None:
            raise RuntimeError("incomplete or malformed guest hash: " + label)
        return match.group(1)

    def stop(self):
        exits = []
        failures = []
        for name, child in reversed(self.children):
            forced = False
            try:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=10)
                        forced = True
            except (OSError, subprocess.SubprocessError) as error:
                # Keep this failure while still stopping the other owned child.
                failures.append({"name": name, "error": str(error)})
            exits.append({"name": name, "pid": child.pid, "returncode": child.returncode, "forced_kill": forced})
        self.result["owned_child_exits"] = exits
        self.result["cleanup_failures"] = failures
        self.result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        self.save()


def run_control(control_type: type[Control], output_name: str) -> int:
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or platform.system() != "Linux" or platform.machine() != "x86_64"):
        raise RuntimeError("this control runs only on disposable GitHub-hosted Linux x86_64")
    import shutil
    sdk = Path(os.environ["ANDROID_HOME"]).resolve(strict=True)
    manager = shutil.which("avdmanager")
    if manager is None:
        raise RuntimeError("avdmanager missing")
    output = Path(os.environ["GITHUB_WORKSPACE"]) / "target" / output_name
    output.parent.mkdir(exist_ok=True)
    control = control_type(output, sdk, Path(manager))
    try:
        control.run()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        control.result["failure"] = str(error)
    finally:
        control.stop()
    return 0 if (control.result.get("completed")
                 and control.result.get("observations_clean")
                 and not control.result["cleanup_failures"]) else 1


def main() -> int:
    return run_control(Control, "android-runtime-control")


if __name__ == "__main__":
    raise SystemExit(main())
