#!/usr/bin/env python3
"""Isolated old-send-chain disclosure: poisoned ACK, honest unknown outcome."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def forge(chain, session, index, plaintext, ad):
    """The adversary receives only one old sending chain and public metadata."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from qperiapt_continuity_reference.traffic import DOMAIN, message_id, step
    next_chain, key = step(chain, index)
    identity = message_id(session, 1, index, 0)
    header = b"QPCMSG03" + session + b"\1" + bytes(8) + index.to_bytes(8, "big") + identity + len(plaintext).to_bytes(4, "big")
    wire = header + ChaCha20Poly1305(key).encrypt(bytes(12), plaintext,
        DOMAIN + b"aead" + header + len(ad).to_bytes(2, "big") + ad)
    return next_chain, identity, wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.resolution import ciphertext_digest
    from resolution_scenario import ResolutionScenario
    from traffic_checks import application
    sources = [*sorted((peer / "qperiapt_continuity_reference").glob("*.py")), *sorted(peer.glob("*.py")),
               *sorted((peer / "native/src").glob("*.rs")), peer / "native/Cargo.toml", peer / "native/Cargo.lock", peer / "requirements.txt"]
    before = {str(p.relative_to(peer)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    native_hash = hashlib.sha256(args.native.read_bytes()).hexdigest()
    scenario = ResolutionScenario(args, archived_version=3)
    try:
        scenario.bootstrap()
        scenario.require(scenario.worker("upgrade", "upgrade_format") == 5, "resolution format")
        original_id, original_wire, _lost_ack = scenario.forward("genuine-send", acknowledge=False)
        # The prior admissible ACK is retained only in the experiment transcript,
        # never supplied to the sender. Ordinary retained-ACK recovery is valid.
        chain = scenario.inspect(lambda _snapshot, state: state.traffic.traffic(0)._send)
        for index in (1, 2):
            plain = b"old-chain injection " + bytes([index])
            chain, identity, wire = forge(chain, scenario.session, index, plain, b"rekey AD")
            scenario.native_call("forged-receive-" + str(index), 7, application(b"rekey AD", wire), plain)
            poisoned = scenario.native_call("forged-consume-" + str(index), 10, identity)
        chain = b""
        scenario.require(int.from_bytes(poisoned[-40:-32], "big") == 3, "actual poisoned consumption floor")
        scenario.unchanged_refusal("poisoned-ACK-rejected", "accept_acknowledgement", (poisoned,), "ACK prefix")
        scenario.require(scenario.output_bytes("original-outbox-retained", "resume", (original_id,)) == original_wire,
                         "poisoned ACK discarded genuine outbox")
        for target in range(1, 4):
            scenario.settle(target, "epoch-" + str(target))
            scenario.forward("fresh-before-resolution-" + str(target))
        offer = scenario.native_call("original-offer-4", 17)
        scenario.unchanged_refusal("unsettled-history-blocks-4", "respond_rekey_offer", (offer,), "unsettled history capacity")
        scenario.native_call("native-reopen-original-offer", 12, expected=b"reopened")
        scenario.require(scenario.native_call("native-replay-original-offer", 17) == offer, "native offer replaced")
        report = scenario.worker("unknown-report", "begin_closed_epoch_resolution", (bytes(8),))
        scenario.require(report["acknowledged_before"] == 0 and report["sent"] == 1 and report["outgoing"] ==
            [{"id": original_id.hex(), "ciphertext_digest": ciphertext_digest(original_wire).hex()}], "honest outcome not reported")
        scenario.application_decision("explicit-unknown-application", 1, report)
        scenario.worker("application-ACK", "acknowledge_closed_epoch_resolution", (bytes(8), bytes.fromhex(report["id"])))
        scenario.require(scenario.worker("honest-unknown-status", "status", (original_id,)) == "DeliveryUnknown", "poisoned ACK turned into delivery success")
        response = scenario.output_bytes("same-offer-4-response", "respond_rekey_offer", (offer,))
        final = scenario.native_call("same-offer-4-final", 18, response)
        receipt = scenario.output_bytes("same-offer-4-receipt", "finish_rekey", (final,))
        scenario.native_call("same-offer-4-confirmed", 19, receipt, (4).to_bytes(8, "big"))
        scenario.require(scenario.worker("independent-4-confirmed", "rekey_progress") == [4, 4, 4, 0], "same original target did not complete")
        for target in (5, 6):
            scenario.settle(target, "epoch-" + str(target))
            scenario.forward("fresh-after-resolution-" + str(target))
        scenario.require(scenario.worker("collected-unknown-status", "status", (original_id,)) == "Retired", "old epoch not collected")
        scenario.native_call("close", 3, expected=b"closed")
        scenario.require(scenario.native.process.wait(timeout=5) == 0, "native shutdown")
        scenario.require(before == {str(p.relative_to(peer)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
                         and native_hash == hashlib.sha256(args.native.read_bytes()).hexdigest(), "source changed")
        result = {"scope": "Finite old-send-chain disclosure against a real Rust peer; explicit unknown-outcome accounting restores bounded-history progress, not a PCS proof",
                  "disclosed": ["epoch-zero send chain after original message zero"],
                  "not_provided_to_forge": ["identity signing owner", "rekey root", "KEM material", "journal wrapping key", "ACK key"],
                  "forged_indices": [1, 2], "honest_send_count": 1, "peer_consumed_floor": 3,
                  "original_valid_ACK_deliberately_not_delivered": True,
                  "outbox_preserved_after_ACK_refusal": True, "target_four_refused_before_resolution": True,
                  "same_original_offer_completed_after_resolution": True, "epochs": 6, "resolution": report,
                  "worker_operations": scenario.driver.operations, "native_commands": scenario.native.commands,
                  "control_steps": scenario.steps, "application_decisions": scenario.decisions,
                  "source_files": before, "native_sha256": native_hash,
                  "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
                  "private_keys_or_images_in_artifact": False, "hardware_power_loss": False, "general_PCS_proof": False}
        (scenario.output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"epochs": 6, "forged_indices": [1, 2], "worker_operations": len(scenario.driver.operations), "native_commands": len(scenario.native.commands)}))
    finally:
        scenario.native.close()


if __name__ == "__main__":
    main()
