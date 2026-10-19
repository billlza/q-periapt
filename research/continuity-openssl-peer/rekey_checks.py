#!/usr/bin/env python3
"""Independent rekey computations versus actual durable Rust epoch cutovers.

The Python control/traffic state in this lane is volatile. The separate epoch-zero
persistence lane is unchanged; this is not independent durable rekey admission.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-root", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from qperiapt_continuity_reference.provider import load_provider
    cryptography, backend = load_provider(args.provider_root)
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from fixture_inputs import load
    from qperiapt_continuity_reference.bootstrap import Initiator
    from qperiapt_continuity_reference.kem import HybridPrivate
    from qperiapt_continuity_reference.rekey import RekeyScope, digest, genesis
    from qperiapt_continuity_reference.traffic import VolatileTraffic, message_id
    from qperiapt_continuity_reference.wire import SigningKey, require
    from run import Counterpart
    from traffic_checks import application
    output = args.output.resolve()
    output.mkdir()
    native = Counterpart(args.native.resolve(strict=True), output)
    signer = SigningKey()
    refusals, epochs = [], []

    def refused(name, operation):
        try:
            operation()
        except (ValueError, InvalidSignature, InvalidTag) as error:
            refusals.append({"case": name, "exception": type(error).__name__})
        else:
            raise ValueError("negative rekey accepted: " + name)

    def command(name, number, wire=b"", expected=None, status=1):
        return native.command(name, number, wire, status, expected)

    def progress(name, expected):
        wire = command(name, 16)
        values = [int.from_bytes(wire[i:i+8], "big") for i in range(0, len(wire), 8)]
        require(len(wire) == 32 and values == expected, "native directional progress")

    def altered(value):
        return value[:-1] + bytes([value[-1] ^ 1])

    traffic = None
    try:
        require(native.transfer(signer.public().raw) == b"\1ready", "native enrollment")
        _, _, context = load(output / "public", 150)
        bootstrap = Initiator(context, signer, 150)
        initial = bootstrap.initial(150)
        reply = command("initial", 4, initial)
        final = bootstrap.finish(reply, 150)
        session = command("final", 5, final)
        require(session == bootstrap.session_id(), "bootstrap session")
        command("activate", 6, expected=session)
        traffic = bootstrap.activate_volatile_traffic(170)
        root, predecessor = traffic._rekey, genesis(session, context.digest)
        bootstrap.close()
        previous_ack = None
        for epoch in range(1, 9):
            label = f"epoch-{epoch}-"
            context.check_established(170)
            scope = RekeyScope(context, session, epoch-1, predecessor)
            prior_sent, prior_received = traffic._sent, traffic._received
            require(not traffic._outbox and not traffic._inbox and not traffic._skipped
                    and traffic._send_floor == prior_sent and traffic._receive_floor == prior_received,
                    "test history must be fully settled before attesting")
            early_outgoing = early_incoming = None
            plaintext = (b"", b"independent rekey application", bytes(range(256))*64)[epoch % 3]
            ad = bytes(range(256))*4 if epoch % 3 == 2 else b"rekey application"
            if epoch % 2:
                key = HybridPrivate()
                offer_body = scope.offer_body(key.public())
                offer = signer.sign(9, offer_body)
                bad_scope = signer.sign(9, offer_body[:152] + bytes([offer_body[152] ^ 1]) + offer_body[153:])
                command(label+"wrong-predecessor", 14, bad_scope, b"Protocol(Scope)", 2)
                response = command(label+"response", 14, offer)
                require(command(label+"response-replay", 14, offer) == response, "response replay")
                progress(label+"response-progress", [epoch-1, epoch-1, epoch-1, epoch])
                refused(label+"bad-response-signature", lambda: scope.verify_response(offer, altered(response), key, root))
                refused(label+"wrong-root", lambda: scope.verify_response(offer, response, key, bytes(32)))
                refused(label+"wrong-KEM-owner", lambda: scope.verify_response(offer, response, HybridPrivate(), root))
                next_root = scope.verify_response(offer, response, key, root)
                body = scope.final_body(offer, response, next_root, prior_sent)
                final = signer.sign(11, body)
                command(label+"signed-bad-final-MAC", 15, signer.sign(11, altered(body)), b"Protocol(Authentication)", 2)
                fresh = VolatileTraffic._from_epoch(context, session, epoch, next_root,
                                                    scope.traffic_material(offer, response, next_root), 170)
                outgoing_id = fresh.next_id(170)
                early_outgoing = fresh.send(outgoing_id, plaintext, ad, 170)
                command(label+"future-traffic", 7, application(ad, early_outgoing), b"Suspended", 2)
                receipt = command(label+"receipt", 15, final)
                refused(label+"bad-receipt-signature", lambda: scope.verify_receipt(offer, response, final, altered(receipt), next_root))
                require(scope.verify_receipt(offer, response, final, receipt, next_root) == prior_received,
                        "responder close count")
                command(label+"reopen-receipt", 12, expected=b"reopened")
                require(command(label+"receipt-replay", 15, final) == receipt, "receipt replay after reopen")
            else:
                offer = command(label+"offer", 17)
                require(command(label+"offer-replay", 17) == offer, "offer replay")
                public = scope.open(0, offer)[153:]
                refused(label+"bad-offer-signature", lambda: scope.open(0, altered(offer)))
                ciphertext, shared = context.sdk.encapsulate(public, digest(b"response-kem", offer))
                body, next_root = scope.response_body(offer, ciphertext, shared, root)
                response = signer.sign(10, body)
                command(label+"signed-bad-response-MAC", 18, signer.sign(10, altered(body)), b"Protocol(Authentication)", 2)
                final = command(label+"final", 18, response)
                require(scope.verify_final(offer, response, final, next_root) == prior_received, "proposer close count")
                progress(label+"final-progress", [epoch-1, epoch, epoch-1, epoch])
                refused(label+"bad-final-signature", lambda: scope.verify_final(offer, response, altered(final), next_root))
                command(label+"reopen-final", 12, expected=b"reopened")
                require(command(label+"final-replay", 18, response) == final, "final replay after reopen")
                incoming_id = command(label+"early-id", 8)
                early_incoming = command(label+"early-send", 9, incoming_id + application(ad, plaintext))
                refused(label+"future-traffic", lambda: traffic.receive(early_incoming, ad, 170))
                fresh = VolatileTraffic._from_epoch(context, session, epoch, next_root,
                                                    scope.traffic_material(offer, response, next_root), 170)
                receipt_body = scope.receipt_body(offer, response, final, next_root, prior_sent)
                receipt = signer.sign(12, receipt_body)
                command(label+"signed-bad-receipt-MAC", 19, signer.sign(12, altered(receipt_body)), b"Protocol(Authentication)", 2)
                command(label+"accept-receipt", 19, receipt, epoch.to_bytes(8,"big"))
                command(label+"accept-receipt-replay", 19, receipt, epoch.to_bytes(8,"big"))
            progress(label+"completed", [epoch, epoch, epoch, 0])
            predecessor = scope.completed(offer, response, final, receipt, next_root)
            other_session = altered(session)
            other = RekeyScope(context, other_session, epoch-1,
                               genesis(other_session, context.digest) if epoch == 1 else scope.predecessor)
            for flight, control in enumerate((offer, response, final, receipt)):
                offset = 4 + int.from_bytes(control[:4], "big")
                bad_pq = control[:offset] + bytes([control[offset] ^ 1]) + control[offset+1:]
                refused(label+f"flight-{flight}-MLDSA", lambda flight=flight, bad_pq=bad_pq: scope.open(flight, bad_pq))
                refused(label+f"flight-{flight}-other-session", lambda flight=flight, control=control: other.open(flight, control))
            root = next_root
            traffic.close()
            traffic = fresh
            identity = message_id(session, 1, 0, epoch)
            wire = early_outgoing if early_outgoing is not None else traffic.send(identity, plaintext, ad, 170)
            command(label+"receive", 7, application(ad, wire), plaintext)
            ack = command(label+"consume", 10, identity)
            require(traffic.accept_acknowledgement(ack, 170) == 1, "new epoch consumption")
            if previous_ack is not None:
                refused(label+"cross-epoch-ACK", lambda: traffic.accept_acknowledgement(previous_ack, 170))
            previous_ack = ack
            incoming_id = message_id(session, 2, 0, epoch)
            incoming = early_incoming if early_incoming is not None else command(label+"send", 9, incoming_id + application(ad, plaintext))
            refused(label+"wrong-AD", lambda: traffic.receive(incoming, b"wrong", 170))
            require(traffic.receive(incoming, ad, 170) == (incoming_id, plaintext), "new epoch plaintext")
            own_ack = traffic.consume(incoming_id, 170)
            command(label+"acknowledge", 11, own_ack, (1).to_bytes(8,"big"))
            command(label+"native-ACK-replay", 20, epoch.to_bytes(8,"big"), ack)
            require(traffic.next_id(170) == message_id(session, 1, 1, epoch), "epoch send index")
            for name, value in [("offer",offer),("response",response),("final",final),("receipt",receipt)]:
                (output/(label+name)).write_bytes(value)
            epochs.append({"epoch":epoch,"proposer":scope.role(0),"predecessor":predecessor.hex(),
                           "plaintext_bytes":len(plaintext),"AD_bytes":len(ad),"bidirectional_new_epoch_traffic":True})
        refused("expired-traffic", lambda: traffic.next_id(200))
        command("close", 3, expected=b"closed")
        require(native.process.wait(timeout=5) == 0, "native close")
        sources=[*sorted((peer/"qperiapt_continuity_reference").glob("*.py")),*sorted(peer.glob("*.py")),*sorted((peer/"native/src").glob("*.rs")),peer/"native/Cargo.toml",peer/"native/Cargo.lock",peer/"requirements.txt"]
        report={"scope":"Independent volatile four-flight rekey computations and traffic versus actual Rust journal cutovers; independent durable rekey remains unimplemented",
                "epochs":epochs,"native_commands":native.commands,"refusals":refusals,"native_journal_reopens":8,
                "native_sha256":hashlib.sha256(args.native.read_bytes()).hexdigest(),
                "source_files":{str(p.relative_to(peer)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources},
                "provider":{"cryptography":cryptography.__version__,"openssl":backend.openssl_version_text()},
                "independent_durable_rekey":False,"post_compromise_security_proven":False}
        (output/"RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps({"epochs":len(epochs),"native_commands":len(native.commands),"refusals":len(refusals)}))
    finally:
        if traffic is not None: traffic.close()
        native.close()


if __name__ == "__main__":
    main()
