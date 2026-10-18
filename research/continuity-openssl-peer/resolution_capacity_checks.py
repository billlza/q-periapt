#!/usr/bin/env python3
"""A real maximum-size retained plaintext report through the direct host API."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    from peer.durable import Session
    from peer.resolution import ciphertext_digest
    from resolution_scenario import ResolutionScenario
    from signing_fixture import read
    from traffic_checks import application
    sources = [*sorted((peer / "peer").glob("*.py")), *sorted(peer.glob("*.py")),
               *sorted((peer / "native/src").glob("*.rs")), peer / "native/Cargo.toml", peer / "native/Cargo.lock", peer / "requirements.txt"]
    before = {str(p.relative_to(peer)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    native_hash = hashlib.sha256(args.native.read_bytes()).hexdigest()
    scenario = ResolutionScenario(args, archived_version=3, send_budget=1024)
    owner = None
    try:
        scenario.bootstrap()
        scenario.require(scenario.worker("upgrade", "upgrade_format") == 4, "maximum report format")
        owner = Session.open(scenario.path, scenario.scope, scenario.key, scenario.context)
        received = []
        for index in range(64):
            identity = scenario.native_call("native-id-" + str(index), 8)
            plain = bytes([index]) * 16384
            wire = scenario.native_call("native-send-" + str(index), 9, identity + application(b"maximum report", plain))
            scenario.require(owner.receive(wire, b"maximum report", 170) == (identity, plain), "full-size native plaintext")
            received.append((identity, plain, wire))
        signer = read(scenario.signer_path)
        offer = owner.prepare_rekey_offer(signer, 170)
        response = scenario.native_call("rekey-response", 14, offer)
        final = owner.accept_rekey_response(response, signer, 170)
        receipt = scenario.native_call("rekey-receipt", 15, final)
        scenario.require(owner.accept_rekey_receipt(receipt, 170) == 1, "closed maximum epoch")
        report = owner.begin_closed_epoch_resolution(0, 170).public_record()
        scenario.require(len(report["incoming"]) == 64 and not report["outgoing"] and not report["skipped"], "maximum report inventory")
        for index, row in enumerate(report["incoming"]):
            scenario.require(row == {"id": received[index][0].hex(), "index": index, "plaintext": received[index][1].hex()}, "retained full plaintext")
        owner.close(); owner = Session.open(scenario.path, scenario.scope, scenario.key, scenario.context)
        scenario.require(owner.begin_closed_epoch_resolution(0, 170).public_record() == report, "maximum report reopen")
        scenario.application_decision("maximum-python-application", 1, report)
        owner.acknowledge_closed_epoch_resolution(0, bytes.fromhex(report["id"]), 170)
        with owner._state() as (_snapshot, state):
            traffic = state.traffic.traffic(0)
            scenario.require(not traffic._inbox and traffic._receive_floor == 0 and traffic._received == 64, "maximum report forged consumption")
        native = scenario.native_report("maximum-native-report")
        scenario.require(native["outgoing"] == [{"id": identity.hex(), "ciphertext_digest": ciphertext_digest(wire).hex()}
                         for identity, _plain, wire in received], "native maximum outgoing report")
        scenario.application_decision("maximum-native-application", 2, native)
        scenario.native_call("native-resolution-ACK", 25, bytes(8) + bytes.fromhex(native["id"]), bytes.fromhex(native["id"]))
        for index in (0, 63):
            scenario.native_call("native-unknown-" + str(index), 27, received[index][0], b"DeliveryUnknown")
        scenario.native_call("close", 3, expected=b"closed")
        scenario.require(scenario.native.process.wait(timeout=5) == 0, "native shutdown")
        scenario.require(before == {str(p.relative_to(peer)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
                         and native_hash == hashlib.sha256(args.native.read_bytes()).hexdigest(), "source changed")
        (scenario.output / "REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
        result = {"scope": "Actual 64-by-16-KiB plaintext report through direct Python host API and actual Rust outgoing report; no report size cap was lowered",
                  "incoming_messages": 64, "retained_plaintext_bytes": 1048576, "native_unknown_outgoing": 64,
                  "report_reopened_exactly": True, "original_consumed_floor": 0, "original_observed_count": 64,
                  "native_commands": scenario.native.commands, "worker_operations": scenario.driver.operations,
                  "application_decisions": scenario.decisions, "source_files": before, "native_sha256": native_hash,
                  "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
                  "private_keys_or_images_in_artifact": False, "hardware_power_loss": False, "Python_physical_erasure": False}
        (scenario.output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"incoming_messages": 64, "plaintext_bytes": 1048576, "native_commands": len(scenario.native.commands)}))
    finally:
        if owner is not None:
            owner.close()
        scenario.native.close()


if __name__ == "__main__":
    main()
