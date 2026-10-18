#!/usr/bin/env python3
"""Independent persisted session interoperating with the actual Rust journal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-root", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    peer_root = Path(__file__).resolve().parent
    provider = args.provider_root.resolve(strict=True)
    sys.path.append(str(peer_root))
    from provider import load_provider
    cryptography, backend = load_provider(provider)
    from fixture_inputs import load
    from peer.durable import Session, owner_binding
    from peer.journal import Scope
    from peer.state_codec import decode
    from peer.wire import SigningKey, require
    from run import Counterpart
    from traffic_checks import application
    output = args.output.resolve()
    output.mkdir()
    native_output = output / "native"
    native_output.mkdir()
    private = Path(tempfile.mkdtemp(prefix="qperiapt-independent-session-")).resolve()
    require(not private.is_relative_to(output), "private session inside artifact output")
    (output / "private-fixture-path").write_text(str(private) + "\n")
    counterpart = Counterpart(args.native.resolve(strict=True), native_output)
    signer = SigningKey()
    results = []
    try:
        require(counterpart.transfer(signer.public().raw) == b"\1ready", "native enrollment")
        _, _, context = load(native_output / "public", 150)
        key = os.urandom(32)
        scope = Scope(os.urandom(32), owner_binding(context), context.digest)
        configuration = private / "configuration"
        fd = os.open(configuration, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key + scope.wire()); stream.flush(); os.fsync(stream.fileno())
        path = private / "session"
        path.mkdir(mode=0o700)
        owner = Session.create(path, scope, key, context, signer, 150)
        initial = owner.initial(150)
        waiting = owner._journal.read().payload
        malformed = {
            "snapshot-truncated": waiting[:-1],
            "snapshot-trailing": waiting + b"\0",
            "snapshot-unknown-phase": waiting[:40] + b"\x09" + waiting[41:],
            "snapshot-wrong-context": waiting[:8] + bytes([waiting[8] ^ 1]) + waiting[9:],
            "snapshot-wrong-KEM-owner": waiting[:5858] + bytes([waiting[5858] ^ 1]) + waiting[5859:],
            "snapshot-wrong-first-secret": waiting[:-1] + bytes([waiting[-1] ^ 1]),
        }
        codec_refusals = []
        for name, payload in malformed.items():
            try:
                restored = decode(payload, context)
            except ValueError:
                codec_refusals.append(name)
            else:
                restored.close()
                raise ValueError("malformed snapshot accepted: " + name)
        owner.close()
        signer = None  # The restarted workers receive no identity signing key.

        from session_driver import SessionDriver
        driver = SessionDriver(output, provider, native_output / "public", configuration, path)
        worker, results = driver.run, driver.operations

        require(bytes.fromhex(worker("reopened-initial", "initial", now=150)) == initial, "initial changed across process")
        reply = counterpart.command("persisted-initial", 4, initial, 1)
        worker("lost-final-result", "finish", (reply,), now=150, cut="protocol:final-committed")
        require(worker("confirmed-status", "status") == "Confirmed", "lost final not committed")
        worker("expired-final-refused", "finish", (reply,), now=170, refusal="expired or premature authority")
        worker("expired-initial-refused", "initial", now=170, refusal="expired or premature authority")
        final = bytes.fromhex(worker("recover-final", "finish", (reply,), now=150))
        session = counterpart.command("persisted-final", 5, final, 1)
        require(counterpart.command("activate-native", 6, b"", 1) == session, "native activation")
        require(bytes.fromhex(worker("activate-independent", "activate")) == session, "independent activation")
        identity = bytes.fromhex(worker("original-id", "next_id"))
        plaintext, ad = b"original persisted operation", b"session application context"
        worker("reserved-interruption", "send", (identity, plaintext, ad), cut="protocol:send-reserved")
        require(worker("reserved-status", "status", (identity,)) == "Reserved", "missing original reservation")
        head = (path / "head").read_bytes()
        worker("conflicting-reservation", "send", (identity, b"changed", ad), refusal="conflicting reserved send")
        require((path / "head").read_bytes() == head, "conflict altered reservation")
        worker("committed-interruption", "resume", (identity,), cut="protocol:send-committed")
        require(worker("committed-status", "status", (identity,)) == "Committed", "send not committed")
        wire = bytes.fromhex(worker("recover-ciphertext", "resume", (identity,)))
        require(bytes.fromhex(worker("repeat-ciphertext", "resume", (identity,))) == wire, "ciphertext replay differs")
        next_id = bytes.fromhex(worker("next-slot", "next_id"))
        require(int.from_bytes(next_id[8:16], "big") == 1, "send advanced more than once")
        require(counterpart.command("receive-independent", 7, application(ad, wire), 1) == plaintext, "native decryption")
        ack = counterpart.command("consume-independent", 10, identity, 1)
        worker("ACK-publication-cut", "accept_acknowledgement", (ack,), cut="committed:head")
        require(worker("acknowledged-status", "status", (identity,), now=200) == "Acknowledged", "ACK recovery")
        worker("expired-output-refused", "resume", (identity,), now=200, refusal="expired or premature authority")

        native_id = counterpart.command("native-id", 8, b"", 1)
        native_plain, native_ad = bytes(range(256)) * 64, bytes(range(256)) * 4
        native_wire = counterpart.command("native-send", 9, native_id + application(native_ad, native_plain), 1)
        before = (path / "head").read_bytes()
        worker("invalid-receive", "receive", (native_wire, b"wrong"), refusal="InvalidTag")
        require((path / "head").read_bytes() == before, "failed receive advanced state")
        worker("receive-result-lost", "receive", (native_wire, native_ad), cut="protocol:receive-committed")
        received = worker("recover-plaintext", "receive", (native_wire, native_ad))
        require(received == [native_id.hex(), native_plain.hex()], "recovered plaintext differs")
        stable = (path / "head").read_bytes()
        require(worker("duplicate-plaintext", "receive", (native_wire, native_ad)) == received,
                "duplicate plaintext differs")
        require((path / "head").read_bytes() == stable, "duplicate receive rewrote storage")
        worker("consumption-result-lost", "consume", (native_id,), cut="protocol:consumption-committed")
        consumption = bytes.fromhex(worker("recover-ACK", "acknowledgement"))
        require(counterpart.command("native-accept-ACK", 11, consumption, 1) == (1).to_bytes(8, "big"), "native ACK verification")
        worker("consumed-receive", "receive", (native_wire, native_ad), refusal="retired receive")
        require(bytes.fromhex(worker("duplicate-consumption", "consume", (native_id,))) == consumption,
                "consumption ACK replay differs")
        counterpart.command("close", 3, b"", 1, b"closed")
        require(counterpart.process.wait(timeout=5) == 0, "native close")
        sources = [*sorted((peer_root / "peer").glob("*.py")), *sorted(peer_root.glob("*.py")),
                   *sorted((peer_root / "native" / "src").glob("*.rs")), peer_root / "native/Cargo.toml",
                   peer_root / "native/Cargo.lock", peer_root / "requirements.txt"]
        report = {"scope": "Independent local-only bootstrap/epoch-zero persistence and process recovery against a live Rust journal; no rekey/witness/lifecycle or release qualification",
                  "process_kills": sum('signal' in item for item in results), "worker_operations": results,
                  "codec_refusals": codec_refusals,
                  "native_commands": counterpart.commands, "source_files": {str(p.relative_to(peer_root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                  "provider": {"cryptography": cryptography.__version__, "openssl": backend.openssl_version_text()},
                  "hardware_power_loss": False, "native_process_restart": False,
                  "private_key_or_image_uploaded": False, "identity_signing_key_in_journal": False}
        (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"process_kills": report["process_kills"], "worker_operations": len(results), "native_commands": len(counterpart.commands)}))
    finally:
        counterpart.close()


if __name__ == "__main__":
    main()
