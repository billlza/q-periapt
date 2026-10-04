"""Isolated hosted ADB experiment; never a package-admission or release gate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import zipfile

from bounded_process import capture_stdout, write_stdout_at

ROOT = Path(__file__).resolve().parent.parent
PROTOCOL_MODES = ("uninstalled-pipe-copy", "uninstalled-shell-copy")
UNINSTALLED_MODES = (*PROTOCOL_MODES, "uninstalled-file-copy")
MODES = ("apk-path-only", "apk-pipe-copy", "apk-file-copy", *UNINSTALLED_MODES)
ARCHIVE_SHA256 = "1cf08883b24b280288b5c964d3e05e9dcac47f62b455b97dc026bf7299851084"
APK_MEMBER = "agp_sdk_full_release--runtime--artifacts--qperiapt-android-smoke.apk"
APK_SHA256 = "e2548ac0343802f35bc880804805d60448bf131e436dd0e7e0fb859d0f900724"
APK_BYTES = 13608912
APK_SOURCE_COMMIT = "9830732a8bfdafe98b70fce7efce085d7085b1f1"
PACKAGE = "dev.qperiapt.androidsmoke"
BLOB_PATH = "/data/local/tmp/qperiapt-transport-probe.bin"
TRANSPORT_LOG_BYTES = 16 * 1024 * 1024
LOG_MARKER = "QP_APK_TRANSPORT_MARKER_01"


def independent_marker(data: bytes) -> bool:
    """Match a guest logcat line, never a traced shell command mentioning it."""
    return re.search(rb"(?m)^[^\r\n]*\bI(?:/QPeriaptProbe\(\s*\d+\)|\s+QPeriaptProbe)"
                     rb"\s*:\s*QP_APK_TRANSPORT_MARKER_01\r?$", data) is not None


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare_archive(directory: Path, destination: Path) -> dict:
    """Read only the fixed public APK from a byte-pinned historical CI artifact."""
    entries = list(directory.iterdir())
    if len(entries) != 1 or entries[0].is_symlink() or not entries[0].is_file():
        raise ValueError("expected exactly one public probe ZIP")
    archive = entries[0]
    if archive.stat().st_size != 51444273 or digest(archive) != ARCHIVE_SHA256:
        raise ValueError("probe artifact bytes differ")
    with zipfile.ZipFile(archive) as container:
        entry = container.getinfo(APK_MEMBER)
        if entry.file_size != APK_BYTES:
            raise ValueError("probe APK width differs")
        data = container.read(entry)
        proof = json.loads(container.read("agp_sdk_full_release--proof.json"))
    if (hashlib.sha256(data).hexdigest() != APK_SHA256
            or proof["git_commit"] != APK_SOURCE_COMMIT
            or proof["artifacts"]["smoke_apk_sha256"] != APK_SHA256):
        raise ValueError("probe APK identity differs")
    with destination.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return dict(artifact_id=11309464232, producer_run=37219996163, archive_sha256=ARCHIVE_SHA256,
                apk_sha256=APK_SHA256, apk_bytes=APK_BYTES, producer_checkout=APK_SOURCE_COMMIT,
                failed_push_apk_identity_proven=False)


def remote_path(data: bytes) -> str:
    match = re.fullmatch(rb"package:(/data/app/[A-Za-z0-9_+=~\/.-]+/base\.apk)\r?\n", data)
    if match is None or b".." in match[1] or b"//" in match[1]:
        raise ValueError("package path is unavailable or noncanonical")
    return match[1].decode("ascii")


def copy_observation(path: Path) -> dict:
    size = path.stat().st_size
    if size > APK_BYTES:
        raise ValueError("probe copy exceeds APK bound")
    value = digest(path)
    return dict(bytes=size, sha256=value, exact=size == APK_BYTES and value == APK_SHA256)


def process_identity(data: bytes, pid: bytes, name: bytes) -> tuple[bytes, bytes, int, int]:
    prefix = pid + b" (" + name + b") "
    if not data.startswith(prefix):
        raise ValueError("tracked guest process name or PID differs")
    # This fixed API35 kernel emits all 52 proc stat fields and one final LF.
    # An exit-zero truncated cat is still an invalid observation.
    fields = data[len(prefix):-1].split(b" ")
    if (not data.endswith(b"\n") or data.count(b"\n") != 1 or len(fields) != 50
            or fields[0] not in (b"R", b"S", b"D", b"T", b"t", b"I", b"W", b"K", b"P")
            or any(re.fullmatch(rb"-?[0-9]+", value) is None for value in fields[1:])
            or not fields[1].isdigit() or not fields[19].isdigit() or int(fields[19]) == 0):
        raise ValueError("tracked guest process is dead or has malformed identity")
    return pid, name, int(fields[1]), int(fields[19])


def direct_copy(argv, destination: Path, errors: Path, timeout: int, environment) -> dict:
    """Comparison arm: same command/deadline, stdout directly to a size-limited file.

    The outer probe owns the entire process group. This path has no pipe reader,
    and can signal only its own unreaped direct child on timeout.
    """
    def limit():
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE, (APK_BYTES, APK_BYTES))
    with destination.open("xb") as output, errors.open("xb") as diagnostic:
        with subprocess.Popen(argv, stdout=output, stderr=diagnostic, env=environment,
                              stdin=subprocess.DEVNULL, preexec_fn=limit) as child:
            identity = dict(client_pid=child.pid, client_process_group=os.getpgid(child.pid))
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                raise
    return dict(returncode=code, **identity)


class Experiment:
    def __init__(self, mode: str, work: Path, socket: str, serial: str):
        if mode not in MODES or socket != "localfilesystem:" + str(work / "adb.sock") or serial != "emulator-5584":
            raise ValueError("probe mode or owned transport differs")
        self.mode, self.work = mode, work
        self.output = work.parent
        self.adb = ["/usr/local/lib/android/sdk/platform-tools/adb", "-L", socket, "-s", serial]
        self.environment = dict(os.environ)
        self.deadline = time.monotonic() + 180
        self.events = []
        self.guest_identity = None

    def remaining(self):
        value = min(15, int(self.deadline - time.monotonic()))
        if value < 1:
            raise TimeoutError("probe observation budget exhausted")
        return value

    def record(self, label, **values):
        event = dict(label=label, wall_time_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(), **values)
        self.events.append(event)
        print("APK_TRANSPORT " + json.dumps(event, sort_keys=True), flush=True)

    def query(self, label, args, *, diagnostic=False, environment=None):
        start = time.monotonic_ns()
        try:
            result = capture_stdout(self.adb + args, timeout_seconds=5 if diagnostic else self.remaining(),
                                    maximum_bytes=65536, stderr=subprocess.STDOUT,
                                    environment=self.environment if environment is None else environment)
        except BaseException as error:
            self.record(label, elapsed_ns=time.monotonic_ns()-start, failure_type=type(error).__name__, failure=str(error))
            raise
        self.record(label, elapsed_ns=time.monotonic_ns()-start, returncode=result.returncode,
                    stdout=result.stdout.decode("utf-8", errors="backslashreplace"),
                    output_bytes=len(result.stdout), output_sha256=hashlib.sha256(result.stdout).hexdigest())
        return result

    def protocol_controls(self):
        features = self.query("protocol-features", ["features"])
        names = features.stdout.splitlines()
        if (features.returncode or not names or b"shell_v2" not in names
                or any(re.fullmatch(rb"[a-z0-9_]+", name) is None for name in names)):
            raise RuntimeError("shell_v2 negotiation is unavailable or malformed; no fallback")
        # Both comparison arms perform identical controls on the actual pinned
        # client/image. Trace only these tiny commands, not copied APK contents.
        traced = dict(self.environment, ADB_TRACE="adb")
        for label, command, required in (
            ("protocol-shell-route", ["shell", "-T", "-n", "true"],
             (b"shell,v2,raw:true", b"use_shell_protocol=true shell_type_arg=raw")),
            ("protocol-exec-route", ["exec-out", "true"], (b"exec:true",)),
        ):
            observed = self.query(label, command, environment=traced)
            if observed.returncode or any(value not in observed.stdout for value in required):
                raise RuntimeError("actual ADB service route unconfirmed: " + label)
        errors = self.work / "protocol-control.err"
        command = self.adb + ["shell", "-T", "-n", "sh", "-c",
                              shlex.quote("printf 'QP_OUT\\n'; printf 'QP_ERR\\n' >&2; exit 7")]
        with errors.open("xb") as diagnostic:
            observed = capture_stdout(command, timeout_seconds=self.remaining(), maximum_bytes=65536,
                                      stderr=diagnostic, environment=self.environment)
        with errors.open("rb") as stream:
            stderr = stream.read(65537)
        self.record("protocol-separated-control", returncode=observed.returncode,
                    stdout=observed.stdout.decode("utf-8", errors="backslashreplace"),
                    stderr=stderr.decode("utf-8", errors="backslashreplace"), stderr_bytes=errors.stat().st_size)
        if observed.returncode != 7 or observed.stdout != b"QP_OUT\n" or stderr != b"QP_ERR\n":
            raise RuntimeError("shell_v2 stdout/stderr/exit control differs")

    def confirm_independent_log(self):
        result = self.query("guest-log-marker", ["shell", "log", "-p", "i", "-t", "QPeriaptProbe", LOG_MARKER])
        if result.returncode or result.stdout:
            raise RuntimeError("guest log marker command failed")
        deadline = time.monotonic() + min(3, self.remaining())
        # This file is written by the outer supervisor from emulator output.
        # No adb logcat process supplies this pre-copy observation.
        while True:
            with (self.output / "commands.log").open("rb") as stream:
                data = stream.read(TRANSPORT_LOG_BYTES + 1)
            if len(data) > TRANSPORT_LOG_BYTES:
                raise RuntimeError("independent emulator log exceeds its observation bound")
            if independent_marker(data):
                self.record("independent-log-ready", log_bytes=len(data), log_sha256=hashlib.sha256(data).hexdigest())
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("independent emulator log marker not observed")
            time.sleep(0.05)

    def path(self, label):
        if self.mode in UNINSTALLED_MODES:
            program = f"test -f {BLOB_PATH} && test ! -L {BLOB_PATH} && stat -c %s {BLOB_PATH}"
            result = self.query(label, ["shell", "sh", "-c", shlex.quote(program)])
            if result.returncode or result.stdout != str(APK_BYTES).encode() + b"\n":
                raise RuntimeError("uninstalled blob identity unavailable or changed: " + label)
            return BLOB_PATH
        result = self.query(label, ["shell", "pm", "path", PACKAGE])
        if result.returncode:
            raise RuntimeError("package-path command failed: " + label)
        return remote_path(result.stdout)

    def sample(self, number):
        prefix = f"sample-{number:02d}"
        before = self.path(prefix + "-before")
        exact, code = None, None
        if self.mode != "apk-path-only":
            destination, errors = self.work / (prefix + ".apk"), self.work / (prefix + ".err")
            start = time.monotonic_ns()
            command = self.adb + (["shell", "-T", "-n", "cat", before]
                                 if self.mode == "uninstalled-shell-copy" else ["exec-out", "cat", before])
            if self.mode in ("apk-pipe-copy", *PROTOCOL_MODES):
                descriptor = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with errors.open("xb") as diagnostic:
                        result = write_stdout_at(command, output_directory_fd=descriptor, output_name=destination.name,
                            timeout_seconds=self.remaining(), maximum_bytes=APK_BYTES, stderr=diagnostic,
                            environment=self.environment, retain_nonzero=True)
                    outcome = dict(returncode=result.returncode)
                finally:
                    os.close(descriptor)
            else:
                outcome = direct_copy(command, destination, errors, self.remaining(), self.environment)
            observed = copy_observation(destination)
            code, exact = outcome["returncode"], observed["exact"]
            with errors.open("rb") as diagnostic:
                error_prefix = diagnostic.read(65536)
            # This observation deliberately precedes pm path, including zero-exit
            # short copies. The production failure lacked this byte evidence.
            self.record(prefix + "-copy", elapsed_ns=time.monotonic_ns()-start, command=command, **outcome, **observed,
                        stderr_bytes=errors.stat().st_size, stderr_sha256=digest(errors),
                        stderr_prefix=error_prefix.decode("utf-8", errors="backslashreplace"),
                        stderr_truncated=errors.stat().st_size > len(error_prefix))
        after = self.path(prefix + "-after")
        self.record(prefix + "-result", path_unchanged=before == after, copy_exact=exact, copy_returncode=code)
        if before != after or exact is False or code not in (None, 0):
            raise RuntimeError("copy or package identity changed")
        if self.mode != "apk-path-only":
            destination.unlink()
        self.identity(prefix + "-identity")

    def identity(self, label):
        program = "cat /proc/sys/kernel/random/boot_id; pidof adbd; pidof system_server; cat /proc/uptime"
        state = self.query(label, ["shell", "sh", "-c", shlex.quote(program)])
        lines = state.stdout.splitlines()
        if (state.returncode or len(lines) != 4 or re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", lines[0]) is None
                or any(re.fullmatch(rb"[1-9][0-9]*(?: [1-9][0-9]*){0,15}", line) is None for line in lines[1:3])):
            raise RuntimeError("guest identity unavailable or malformed")
        candidates = [line.split() for line in lines[1:3]]
        if any(len(values) != len(set(values)) for values in candidates):
            raise RuntimeError("guest process census contains duplicate PIDs")
        if self.guest_identity is None:
            if any(len(values) != 1 for values in candidates):
                raise RuntimeError("baseline guest service identity is ambiguous")
            selected = [values[0] for values in candidates]
        else:
            boot, previous = self.guest_identity
            selected = [value[0] for value in previous]
            if boot != lines[0] or any(pid not in values for pid, values in zip(selected, candidates, strict=True)):
                raise RuntimeError("guest boot/adbd/system_server identity changed")
        observed = []
        for pid, name in zip(selected, (b"adbd", b"system_server"), strict=True):
            result = self.query(label + "-" + name.decode() + "-stat", ["shell", "cat", "/proc/" + pid.decode() + "/stat"])
            if result.returncode:
                raise RuntimeError("tracked guest process stat unavailable")
            observed.append(process_identity(result.stdout, pid, name))
        identity = (lines[0], observed)
        if self.guest_identity is not None and identity != self.guest_identity:
            raise RuntimeError("tracked guest process parent or start time changed")
        # Name matching alone can include a second transient/traced process.
        # Keep that census in the event; continuity requires the original PID,
        # name, parent, start time and boot ID, not selecting a replacement PID.
        self.guest_identity = identity

    def run(self):
        primary = None
        completed = 0
        try:
            if self.mode in UNINSTALLED_MODES:
                absent = self.query("package-absence-before", ["shell", "pm", "list", "packages", "dev.qperiapt"])
                if absent.returncode or absent.stdout != b"":
                    raise RuntimeError("uninstalled experiment package absence unconfirmed")
            if self.mode in PROTOCOL_MODES:
                self.confirm_independent_log()
                self.protocol_controls()
            self.identity("baseline-identity")
            for number in range(1, 25):
                self.sample(number)
                completed += 1
        except BaseException as error:
            primary = error
            self.record("experiment-failed", failure_type=type(error).__name__, failure=str(error))
        finally:
            diagnostics = {}
            queries = [("final-state", ["shell", "sh", "-c", shlex.quote("ps -A; cat /proc/meminfo; cat /proc/uptime")]),
                               ("final-logcat", ["logcat", "-d", "-b", "main", "-b", "system", "-b", "crash", "-t", "200", "-v", "threadtime"]),
                               ("final-crash", ["logcat", "-d", "-b", "crash", "-t", "200", "-v", "threadtime"])]
            if self.mode in UNINSTALLED_MODES:
                queries.append(("package-absence-after", ["shell", "pm", "list", "packages", "dev.qperiapt"]))
            for name, args in queries:
                try:
                    result = self.query(name, args, diagnostic=True)
                    if name == "package-absence-after" and (result.returncode or result.stdout != b""):
                        raise RuntimeError("uninstalled experiment final package absence unconfirmed")
                    diagnostics[name] = dict(returncode=result.returncode)
                except Exception as error:
                    diagnostics[name] = dict(failure_type=type(error).__name__, failure=str(error))
            diagnostics_ok = all(item.get("returncode") == 0 for item in diagnostics.values())
            report = dict(schema_version=1, mode=self.mode, status="observations_completed" if primary is None and diagnostics_ok else "observation_failed",
                          completed_samples=completed, requested_samples=24, apk_sha256=APK_SHA256,
                          source_kind="uninstalled_same_bytes" if self.mode in UNINSTALLED_MODES else "installed_apk",
                          events=self.events, diagnostics=diagnostics, release_claim_eligible=False)
            with (self.output / "samples.json").open("x") as stream:
                json.dump(report, stream, indent=2);stream.write("\n")
        if primary is not None:
            raise primary
        if not diagnostics_ok:
            raise RuntimeError("probe final diagnostics did not complete")


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux":
        raise RuntimeError("APK transport probe requires hosted Linux")
    mode, work, socket, serial = sys.argv[1:]
    Experiment(mode, Path(work), socket, serial).run()


if __name__ == "__main__": main()
