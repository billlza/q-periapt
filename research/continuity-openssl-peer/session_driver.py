"""Bounded direct-worker process control shared by session recovery experiments."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time
from worker_process import command as worker_command
from qperiapt_continuity_reference.wire import require


class SessionDriver:
    def __init__(self, output, provider, public, configuration, path, signer_path=None, *, witness_address=None, worker_script="session_worker.py"):
        self.output, self.provider, self.public = output, provider, public
        self.configuration, self.path, self.signer_path = configuration, path, signer_path
        self.operations = []
        self.witness_address = witness_address
        require(worker_script in ("session_worker.py", "registration_worker.py"), "explicit worker profile")
        self.worker_script = worker_script

    def run(self, name, action, arguments=(), now=170, cut=None, refusal=None, with_signer=True):
        output, provider, public = self.output, self.provider, self.public
        configuration, path = self.configuration, self.path
        peer_root, results = Path(__file__).resolve().parent, self.operations
        request = output / (name + ".request.json")
        with request.open("x") as stream:
            json.dump({"action": action, "now": now, "arguments": [x.hex() for x in arguments]}, stream)
            stream.flush(); os.fsync(stream.fileno())
        command = worker_command(peer_root / self.worker_script,
                   "--provider-root", str(provider), "--public", str(public),
                   "--configuration", str(configuration), "--root", str(path), "--request", str(request))
        if with_signer and self.signer_path is not None:
            command += ["--signer", str(self.signer_path)]
        if self.witness_address is not None:
            command += ["--witness-address", self.witness_address]
        if cut is not None:
            command += ["--cut", cut]
        with (output / (name + ".stderr")).open("xb") as stderr:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                                       start_new_session=True, bufsize=0)
            try:
                require(process.stdout is not None, "worker output missing")
                if cut is not None:
                    value = bytearray()
                    deadline = time.monotonic() + 30
                    while not value.endswith(b"\n"):
                        ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
                        require(bool(ready), "worker cut timeout")
                        part = os.read(process.stdout.fileno(), 1)
                        require(bool(part) and len(value) < 128, "worker cut output")
                        value.extend(part)
                    require(json.loads(value) == {"pid": process.pid, "stage": cut},
                            "wrong session worker identity or cut")
                    os.killpg(process.pid, signal.SIGKILL)
                    require(process.wait(timeout=5) == -signal.SIGKILL, "session worker not killed")
                    (output / (name + ".stdout")).write_bytes(value)
                    require((output / (name + ".stderr")).stat().st_size == 0, "killed worker diagnostics")
                    results.append({"case": name, "action": action, "cut": cut, "signal": "SIGKILL",
                                    "worker_pid": process.pid})
                    return None
                received = bytearray()
                deadline = time.monotonic() + 30
                while True:
                    ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
                    require(bool(ready), "worker output timeout")
                    part = os.read(process.stdout.fileno(), min(65536, 65537 - len(received)))
                    if not part:
                        break
                    received.extend(part)
                    require(len(received) <= 65536, "worker output capacity")
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                value = bytes(received)
                (output / (name + ".stdout")).write_bytes(value)
                if refusal is not None:
                    require(process.returncode != 0 and refusal in (output / (name + ".stderr")).read_text(),
                            "wrong session refusal: " + name)
                    require(not value, "failed session released output")
                    results.append({"case": name, "action": action, "refused": refusal})
                    return None
                require(process.returncode == 0 and (output / (name + ".stderr")).stat().st_size == 0,
                        "session worker failed: " + name)
                result = json.loads(value)
                require(set(result) == {"result"}, "worker result schema")
                results.append({"case": name, "action": action, "stdout_sha256": hashlib.sha256(value).hexdigest()})
                return result["result"]
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
