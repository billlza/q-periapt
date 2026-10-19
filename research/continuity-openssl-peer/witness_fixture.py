"""Bounded loopback byte bridge to the actual native witness test provider."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import socket
import threading
import time

from qperiapt_continuity_reference.wire import require


class Bridge:
    def __init__(self, native, output):
        self.native, self.output = native, output
        self.lock = threading.Lock(); self.guard = threading.Lock()
        self.stop = threading.Event(); self.failure = None
        self.fault = None; self.records = []; self.index = 0
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(4); self.listener.settimeout(0.2)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self._run, name="independent-witness-byte-bridge")
        self.thread.start()

    def call(self, name, command, wire=b"", expected=None, status=1):
        with self.lock:
            return self.native.command(name, command, wire, status, expected)

    def arm(self, mode, kind):
        require(mode in ("before", "after", "corrupt"), "fixture fault mode")
        with self.guard:
            require(self.fault is None, "previous witness fault not reached")
            self.fault = (mode, kind)

    def _serve(self, stream):
        deadline = time.monotonic() + 10
        def read(size):
            result = bytearray()
            while len(result) < size:
                stream.settimeout(max(0.001, deadline - time.monotonic()))
                require(time.monotonic() < deadline, "bridge deadline")
                part = stream.recv(size - len(result)); require(bool(part), "truncated bridge request")
                result.extend(part)
            return bytes(result)
        require(int.from_bytes(read(4), "big") == 3674, "bridge request length")
        wire = read(3674); kind = wire[204]
        with self.guard:
            fault = self.fault[0] if self.fault is not None and self.fault[1] == kind else None
            if fault is not None:
                self.fault = None
        name = "witness-attempt-" + str(self.index); self.index += 1
        (self.output / (name + ".request")).write_bytes(wire)
        row = {"case": name, "kind": kind, "fault": fault, "command_id": wire[140:172].hex(),
               "challenge": wire[172:204].hex(), "request_sha256": hashlib.sha256(wire).hexdigest()}
        self.records.append(row)
        if fault == "before":
            row['delivery'] = 'not_dispatched_by_fixture'
            return
        with self.lock:
            result = self.native.exchange_record(name, 31, wire)
        row['native_status'] = result[0]
        if result[0] == 2:
            row['delivery'] = 'native_rejected_no_signed_reply'; row['error'] = result[1:].decode()
            return
        require(result[0] == 1 and len(result) == 3660, "native witness reply shape")
        reply = result[1:]; row['signed_reply_sha256'] = hashlib.sha256(reply).hexdigest()
        (self.output / (name + ".reply")).write_bytes(reply)
        if fault == "after":
            row['delivery'] = 'signed_reply_withheld_by_fixture'
            return
        if fault == "corrupt":
            reply = reply[:-1] + bytes([reply[-1] ^ 1])
        row['delivery'] = 'corrupted_by_fixture' if fault else 'sent'
        row['transport_reply_sha256'] = hashlib.sha256(reply).hexdigest()
        stream.settimeout(max(0.001, deadline - time.monotonic()))
        stream.sendall(len(reply).to_bytes(4, "big") + reply)

    def _run(self):
        try:
            while not self.stop.is_set():
                try:
                    stream, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with stream:
                    self._serve(stream)
        except BaseException as error:
            self.failure = error

    def close(self):
        self.stop.set(); self.thread.join(timeout=12); self.listener.close()
        require(not self.thread.is_alive(), "bridge worker did not stop")
        if self.failure is not None:
            raise RuntimeError("witness bridge failed") from self.failure
        require(self.fault is None, "requested witness fault was not exercised")
