#!/usr/bin/env python3
"""Original sessions established at C1 adopt G(C0, C1 -> C2), with real recovery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def scenario(args, output, witnessed):
    from fixture_inputs import load, load_witness_pin
    from run import Counterpart
    from session_driver import SessionDriver
    from signing_fixture import write
    from traffic_checks import application
    from witness_fixture import Bridge
    from qperiapt_continuity_reference.durable import Session, owner_binding
    from qperiapt_continuity_reference.journal import Scope
    from cryptography.exceptions import InvalidSignature
    from qperiapt_continuity_reference.renewal import verify, verify_established_peer
    from qperiapt_continuity_reference.witness_session import WitnessSession
    from qperiapt_continuity_reference.wire import SigningKey, require

    output.mkdir(); (output / "native").mkdir()
    private = Path(tempfile.mkdtemp(prefix="qperiapt-intermediate-peer-")).resolve()
    require(not private.is_relative_to(output), "private state inside artifact")
    (output / "private-fixture-path").write_text(str(private) + "\n")
    native = Counterpart(args.native.resolve(), output / "native", peer_lifecycle=True,
                         intermediate_peer=True, required_witness=witnessed)
    bridge = None
    try:
        signer = SigningKey()
        require(native.transfer(signer.public().raw) == b"\1ready", "native ready")
        public = output / "native/public"
        pin = load_witness_pin(public) if witnessed else None
        _, _, context = load(public, 210, witness_pin=pin)
        require(context.devices[1].pin.roster_version == 2, "bootstrap must use intermediate C1")
        grant = (public / "peer-renewal-2").read_bytes()
        operation = (public / "peer-renewal-2-operation").read_bytes()
        target = (public / "pin-peer-renewal-2-target").read_bytes()
        refusals = []
        def refuses(name, action):
            try:
                action()
            except (ValueError, InvalidSignature) as error:
                refusals.append({"case": name, "error": str(error)})
            else:
                raise ValueError("accepted invalid peer renewal: " + name)
        def check(wire=grant, device=context.devices[1], policy=context.policy_digest, expected=target):
            return verify_established_peer(wire, device, context.family, policy, expected, now=310)
        verified = check()
        require(verified.previous.digest == context.devices[1].credential
                and verified.original.digest != context.devices[1].credential, "intermediate lineage")
        for offset in (0, 8, 100, 600, 3800, len(grant) - 1):
            altered = grant[:offset] + bytes([grant[offset] ^ 1]) + grant[offset + 1:]
            refuses("mutated-" + str(offset), lambda altered=altered: check(wire=altered))
        refuses("wrong-policy", lambda: check(policy=bytes(32)))
        refuses("wrong-target", lambda: check(expected=bytes(40)))
        refuses("wrong-device", lambda: check(device=context.devices[0]))
        # This same material must remain insufficient to restore an installation
        # whose original credential is C1: G names C0 as its storage owner.
        try:
            verify(grant, context.devices[1], context.family, context.policy_digest, target, now=310)
        except ValueError as error:
            require(str(error) == "renewal key/original credential differs", "wrong local refusal")
        else:
            raise ValueError("local installation accepted another original credential")
        path = private / "session"; path.mkdir(mode=0o700)
        scope = Scope(os.urandom(32), owner_binding(context), context.digest)
        key = os.urandom(32); config = private / "configuration"
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(key + scope.wire()); stream.flush(); os.fsync(stream.fileno())
        signer_path = private / "signer"; write(signer_path, signer)
        if witnessed:
            genesis = WitnessSession.provision(path, scope, key, context, signer, 210)
            bridge = Bridge(native, output)
            bridge.call("trusted-enrollment", 30, genesis.wire(), b"enrolled")
        else:
            Session.create(path, scope, key, context, signer, 210).close()
        call = bridge.call if bridge else lambda name, command, wire=b"", expected=None: native.command(name, command, wire, 1, expected)
        driver = SessionDriver(output, args.provider_root.resolve(), public, config, path, signer_path,
                               witness_address=(bridge.address[0] + ":" + str(bridge.address[1])) if bridge else None)
        worker = driver.run
        def value(name, action, arguments=(), **kw):
            return bytes.fromhex(worker(name, action, arguments, **kw))
        reply = call("bootstrap-response", 4, value("initial", "initial", now=210))
        final = value("final", "finish", (reply,), now=210)
        session = call("bootstrap-complete", 5, final)
        require(value("activate", "activate", now=220) == session, "original session")
        call("native-activate", 6, expected=session)
        identity = value("original-id", "next_id", now=220)
        ciphertext = value("original-send", "send", (identity, b"retained C1 message", b"lineage"), now=220)
        reverse_id = call("reverse-id", 8)
        reverse = call("reverse-send", 9, reverse_id + application(b"lineage", b"retained native response"))
        require(worker("reverse-receive", "receive", (reverse, b"lineage"), now=220)
                == [reverse_id.hex(), b"retained native response".hex()], "original reverse plaintext")
        worker("expired-C1", "resume", (identity,), now=310, refusal="expired or premature authority")
        head = (path / "head").read_bytes()
        worker("wrong-operation", "admit_peer_credential_renewal", (grant, bytes(32), target), now=310,
               refusal="operation differs")
        require((path / "head").read_bytes() == head, "wrong operation changed original state")
        worker("renewal-intent-kill", "admit_peer_credential_renewal", (grant, operation, target),
               now=310, cut="committed:intent")
        if bridge:
            call("witness-reopen", 32, expected=b"witness reopened")
        require(value("original-renewal-retry", "admit_peer_credential_renewal", (grant, operation, target),
                      now=310) == target, "exact original renewal")
        committed = (path / "head").read_bytes()
        require(value("completed-renewal-retry", "admit_peer_credential_renewal", (grant, operation, target),
                      now=310) == target and (path / "head").read_bytes() == committed,
                "completed retry rewrote original head")
        require(value("retained-ciphertext", "resume", (identity,), now=310) == ciphertext, "changed ciphertext")
        require(worker("retained-plaintext", "receive", (reverse, b"lineage"), now=310)
                == [reverse_id.hex(), b"retained native response".hex()], "changed retained plaintext")
        call("native-receive", 7, application(b"lineage", ciphertext), b"retained C1 message")
        ack = call("native-consume", 10, identity)
        require(worker("accept-original-ACK", "accept_acknowledgement", (ack,), now=310) == 1, "original ACK")
        ack = value("consume-original-response", "consume", (reverse_id,), now=310)
        call("native-accept-ACK", 11, ack, (1).to_bytes(8, "big"))
        offer = value("renewed-offer", "prepare_rekey_offer", now=310)
        response = call("renewed-response", 14, offer)
        final = value("renewed-final", "accept_rekey_response", (response,), now=310)
        receipt = call("renewed-receipt", 15, final)
        require(worker("renewed-confirm", "accept_rekey_receipt", (receipt,), now=310) == 1, "renewed epoch")
        revoked = (public / "peer-revoked-roster").read_bytes()
        revoked_target = (public / "pin-peer-revoked-target").read_bytes()
        require(value("revoke", "admit_peer_roster", (revoked, revoked_target), now=310) == revoked_target,
                "durable revocation")
        worker("revoked-old-grant", "admit_peer_credential_renewal", (grant, operation, target),
               now=310, refusal="revoked")
        worker("revoked-send", "next_id", now=310, refusal="revoked")
        result = {"witnessed": witnessed, "session": session.hex(), "worker_operations": driver.operations,
                  "native_commands": native.commands, "witness_attempts": bridge.records if bridge else [],
                  "direct_refusals": refusals,
                  "local_owner_original_mismatch_refused": True,
                  "scope": "C1 bootstrap, C0-rooted G2 peer admission, exact SIGKILL recovery, retained traffic and rekey. Explicit fixture clocks 210/220/310; native traffic remains 220. No real-time expiry or same-account coordinator claim."}
        (output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        if bridge:
            bridge.close()
        native.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    args = arguments()
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    output = args.output.resolve(); output.mkdir()
    root = Path(__file__).resolve().parent
    def inventory():
        paths = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")),
                 *sorted(root.glob("*.py")), *sorted((root / "native/src").glob("*.rs")),
                 root / "native/Cargo.toml", root / "native/Cargo.lock", root / "requirements.txt"]
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    before = inventory()
    profiles = {name: scenario(args, output / name, witnessed)
                for name, witnessed in [("local", False), ("witness", True)]}
    from qperiapt_continuity_reference.wire import require
    require(before == inventory(), "source closure changed during intermediate peer tests")
    report = {"source_files": before, "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
              "profiles": {name: {"worker_operations": len(row["worker_operations"]),
                                   "native_commands": len(row["native_commands"])} for name, row in profiles.items()}}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
