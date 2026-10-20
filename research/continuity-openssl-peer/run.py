#!/usr/bin/env python3
"""Bounded fresh-process interoperability exercise; save only public transcripts."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-root", type=Path, required=True,
                        help="explicit directory containing cryptography 48.0.1; no site/.pth loading")
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


class Counterpart:
    def __init__(self, executable: Path, output: Path, *, send_budget: int | None = None, required_witness=False, peer_lifecycle=False, local_lifecycle=False, short_roster=False, registration=False, registration_extension=False, intermediate_peer=False, account_members=None, enrolled_peer=False, policy_lifecycle=False):
        self.cases = output / "cases"
        self.cases.mkdir()
        self.stderr = (output / "native.stderr").open("xb")
        try:
            command = [str(executable), str(output / "public")]
            if send_budget is not None:
                if type(send_budget) is not int or not 0 < send_budget <= 65535:
                    raise ValueError("explicit native send budget")
                command += ["--send-budget", str(send_budget)]
            if local_lifecycle:
                command += ["--local-lifecycle"]
            if short_roster:
                command += ["--local-roster-expiry"]
            if peer_lifecycle:
                command += ["--peer-lifecycle"]
            if intermediate_peer:
                command += ["--intermediate-peer"]
            if required_witness:
                command += ["--required-witness"]
            if enrolled_peer:
                command += ["--enrolled-peer"]
            if policy_lifecycle:
                command += ["--policy-lifecycle"]
            if registration:
                command += ["--registration"]
            if registration_extension:
                command += ["--registration-extension"]
            if account_members is not None:
                if type(account_members) is not int or account_members not in (3, 32):
                    raise ValueError("shared account requires 3 or 32 fixture members")
                command += ["--shared-account", str(account_members)]
            self.process = subprocess.Popen(command,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                bufsize=0, start_new_session=True)
        except (OSError, ValueError):
            self.stderr.close()
            raise
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("missing native pipes")
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.commands = []

    def transfer(self, data: bytes) -> bytes:
        deadline = time.monotonic() + 30
        wire = len(data).to_bytes(4, "big") + data
        pipe = self.process.stdin.fileno()
        while wire:
            _, ready, _ = select.select([], [pipe], [], max(0, deadline - time.monotonic()))
            if not ready:
                raise TimeoutError("native input deadline")
            count = os.write(pipe, wire[:4096])
            if count == 0:
                raise RuntimeError("native input closed")
            wire = wire[count:]
        prefix = self.read(4, deadline)
        size = int.from_bytes(prefix, "big")
        if not 1 <= size <= 32768:
            raise ValueError("native output capacity")
        return self.read(size, deadline)

    def read(self, size: int, deadline: float) -> bytes:
        result = bytearray()
        pipe = self.process.stdout.fileno()
        while len(result) < size:
            ready, _, _ = select.select([pipe], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                raise TimeoutError("native output deadline")
            part = os.read(pipe, size - len(result))
            if not part:
                raise RuntimeError("native output ended before complete response")
            result.extend(part)
        return bytes(result)

    def exchange_record(self, name: str, command: int, wire: bytes) -> bytes:
        reply = self.transfer(bytes([command]) + wire)
        # Inputs and replies are public protocol bytes, including rejected
        # signed controls. Keep them even when the expected result is wrong.
        (self.cases / (name + ".input")).write_bytes(wire)
        (self.cases / (name + ".output")).write_bytes(reply)
        self.commands.append({"case": name, "command": command, "status": reply[0],
                              "input_sha256": hashlib.sha256(wire).hexdigest(),
                              "output_sha256": hashlib.sha256(reply[1:]).hexdigest(),
                              "error": reply[1:].decode("ascii") if reply[0] == 2 else None})
        return reply

    def command(self, name: str, command: int, wire: bytes, status: int, expected: bytes | None = None) -> bytes:
        reply = self.exchange_record(name, command, wire)
        if reply[0] != status or (expected is not None and reply[1:] != expected):
            raise ValueError("unexpected native result: " + name + ": " + repr(reply[:100]))
        return reply[1:]

    def close(self):
        # Only this newly created process group belongs to the harness.
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=5)
        finally:
            self.process.stdin.close()
            self.process.stdout.close()
            self.stderr.close()


def main() -> None:
    args = arguments()
    sys.path.append(str(Path(__file__).resolve().parent))
    from qperiapt_continuity_reference.provider import load_provider
    cryptography, backend = load_provider(args.provider_root)
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from qperiapt_continuity_reference.authority import authenticate
    from fixture_inputs import load as load_inputs, read_public
    from qperiapt_continuity_reference.bootstrap import Initiator, digest
    from qperiapt_continuity_reference.wire import ORDER, SigningKey, require
    require(sys.platform in ("darwin", "linux"), "this pipe harness requires POSIX")
    output = args.output.resolve()
    output.mkdir()
    native = args.native.resolve(strict=True)
    signer = SigningKey()
    counterpart = Counterpart(native, output)
    refusals = []

    def refused(name, function, reason=None):
        try:
            function()
        except (ValueError, InvalidSignature, InvalidTag) as error:
            if reason is not None and str(error) != reason:
                raise ValueError("wrong rejection boundary: " + name) from error
            refusals.append({"case": name, "exception": type(error).__name__})
        else:
            raise ValueError("negative control accepted: " + name)

    def read(name: str) -> bytes:
        return read_public(output / "public", name)

    try:
        require(counterpart.transfer(signer.public().raw) == b"\1ready", "native preparation")
        pins, materials, context = load_inputs(output / "public", 150)
        require(context.digest == read("expected-context")
                and context.selection == read("expected-selection"), "independent canonical inputs")
        for field in dataclasses.fields(materials):
            original = getattr(materials, field.name)
            changed = original[:-1] + bytes([original[-1] ^ 1])
            refused("material-" + field.name, lambda field=field, changed=changed:
                    authenticate(pins, dataclasses.replace(materials, **{field.name: changed}), 150))
        for field, value in (("sdk_state", bytes(36)), ("policy_digest", bytes(32)),
                             ("policy_version", 2), ("directory", bytes(32))):
            refused("pin-" + field, lambda field=field, value=value:
                    authenticate(dataclasses.replace(pins, **{field: value}), materials, 150))
        for field, value in (("roster_version", 2), ("roster_digest", bytes(32)),
                             ("device", bytes([3]) * 16), ("generation", 2)):
            altered = dataclasses.replace(pins.responder, **{field: value})
            refused("responder-pin-" + field, lambda altered=altered:
                    authenticate(dataclasses.replace(pins, responder=altered), materials, 150))
        for now in (99, 200):
            refused("authority-time-" + str(now), lambda now=now: authenticate(pins, materials, now))
        refused("wrong-local-signer", lambda: Initiator(context, SigningKey(), 150))
        # A separate synthetic verification-key seam isolates confirmation:
        # real KEM ciphertext and valid dual signatures, deliberately wrong MAC.
        # This context is test-only; it is never used as the native peer context.
        synthetic_signer = SigningKey()
        synthetic = Initiator(dataclasses.replace(context, responder=synthetic_signer.public()), signer, 150)
        synthetic_initial = synthetic.initial(150)
        prefix = b"QPBSR001" + context.digest + digest(b"initial-wire", synthetic_initial) + os.urandom(32)
        ciphertext, _secret = context.sdk.encapsulate(synthetic_initial[76:1292], digest(b"kem-reply", prefix))
        invalid_mac_reply = synthetic_signer.sign(6, prefix + ciphertext + bytes(32))
        (output / "confirmation-control.initial").write_bytes(synthetic_initial)
        (output / "confirmation-control.reply").write_bytes(invalid_mac_reply)
        (output / "confirmation-control.public").write_bytes(synthetic_signer.public().raw)
        refused("valid-signatures-invalid-responder-confirmation",
                lambda: synthetic.finish(invalid_mac_reply, 150), "responder confirmation")
        require(synthetic.initial(150) == synthetic_initial, "failed confirmation changed original operation")
        refused("no-session-after-invalid-confirmation", synthetic.session_id)
        synthetic.close()
        initiator = Initiator(context, signer, 150)
        initial = initiator.initial(150)
        refused("initial-expiry", lambda: initiator.initial(200))
        require(initiator.initial(150) == initial, "stable initial")
        # Re-sign the malformed ciphertext: rejection must reach actual KEM
        # confirmation, not stop at a deliberately broken identity signature.
        body = initial[4:2444]
        changed = body[:1288] + bytes([body[1288] ^ 1]) + body[1289:]
        counterpart.command("valid-signature-invalid-kem-confirmation", 1, signer.sign(5, changed), 2, b"Authentication")
        counterpart.command("truncated-initial", 1, initial[:-1], 2, b"Encoding")
        reply = counterpart.command("initial", 1, initial, 1)
        require(len(reply) == 4633, "reply size")
        require(counterpart.command("duplicate-initial", 1, initial, 1) == reply, "native exact initial replay")
        counterpart.command("conflicting-initial", 1, signer.sign(5, body), 2, b"Conflict")
        refused("reply-truncation", lambda: initiator.finish(reply[:-1], 150))
        refused("reply-trailing-byte", lambda: initiator.finish(reply + b"\0", 150))
        changed = bytearray(reply)
        changed[1260] ^= 1
        refused("reply-MLDSA", lambda: initiator.finish(bytes(changed), 150))
        changed_ec = bytearray(reply)
        changed_ec[-64] ^= 1
        refused("reply-ECDSA", lambda: initiator.finish(bytes(changed_ec), 150))
        refused("reply-wrong-purpose", lambda: context.responder.open(reply, 5, 1256))
        s = int.from_bytes(reply[-32:], "big")
        high = reply[:-32] + (ORDER - s).to_bytes(32, "big")
        refused("reply-high-S", lambda: initiator.finish(high, 150))
        final = initiator.finish(reply, 150)
        require(len(final) == 136 and initiator.finish(reply, 150) == final, "exact final replay")
        refused("conflicting-reply", lambda: initiator.finish(reply[:-1] + bytes([reply[-1] ^ 1]), 150))
        refused("completed-replay-expiry", lambda: initiator.finish(reply, 200))
        wrong_final = final[:-1] + bytes([final[-1] ^ 1])
        counterpart.command("invalid-final-confirmation", 2, wrong_final, 2, b"Authentication")
        session = counterpart.command("final", 2, final, 1)
        require(session == initiator.session_id(), "independent session identity")
        require(counterpart.command("duplicate-final", 2, final, 1) == session, "native exact final replay")
        counterpart.command("conflicting-final", 2, wrong_final, 2, b"Conflict")
        initiator.close()
        initiator.close()
        refused("closed-initial", lambda: initiator.initial(150))
        refused("closed-finish", lambda: initiator.finish(reply, 150))
        refused("closed-session", initiator.session_id)
        from traffic_checks import exercise
        traffic_result = exercise(context, signer, counterpart, output, refused)
        counterpart.command("close", 3, b"", 1, b"closed")
        require(counterpart.process.wait(timeout=5) == 0, "native exit")
        for name, value in (("initial.bin", initial), ("reply.bin", reply),
                            ("final.bin", final), ("session.id", session)):
            (output / name).write_bytes(value)
        peer_root = Path(__file__).resolve().parent
        provider_files = {str(Path(module.__file__).resolve()): hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                          for name, module in tuple(sys.modules.items())
                          if name.startswith(("cryptography", "cffi", "_cffi_backend", "pycparser"))
                          and getattr(module, "__file__", None)}
        sources = [*sorted((peer_root / "qperiapt_continuity_reference").glob("*.py")), *sorted(peer_root.glob("*.py")),
                   *sorted((peer_root / "native" / "src").glob("*.rs")), peer_root / "native" / "Cargo.toml",
                   peer_root / "native" / "Cargo.lock", peer_root / "requirements.txt"]
        report = {"scope": "Independent volatile bootstrap/epoch-zero traffic and actual Rust journal; no independent durable state, rekey, witness, installed package or release claim",
                  "provider": {"cryptography": cryptography.__version__, "openssl": backend.openssl_version_text(),
                               "loaded_files": provider_files},
                  "python": {"executable": sys.executable, "version": sys.version},
                  "peer_sources": {str(p.relative_to(peer_root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                  "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
                  "canonical_context_and_selection_equal": True,
                  "three_flight_mutual_confirmation": True,
                  "traffic": traffic_result,
                  "native_commands": counterpart.commands, "python_refusals": refusals,
                  "case_files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sorted(counterpart.cases.iterdir())},
                  "public_files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in sorted((output / "public").iterdir())}}
        (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"three_flight_mutual_confirmation": True,
                          "native_commands": len(counterpart.commands), "python_refusals": len(refusals)}))
    finally:
        counterpart.close()


if __name__ == "__main__":
    main()
