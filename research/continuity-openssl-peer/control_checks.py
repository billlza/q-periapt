#!/usr/bin/env python3
"""Control-only interoperability, interrupted requests and original-target retry."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from collections import deque
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
    from provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    def inventory():
        sources = [*sorted((peer / "peer").glob("*.py")), *sorted(peer.glob("*.py")),
                   *sorted((peer / "native/src").glob("*.rs")), peer / "native/Cargo.toml",
                   peer / "native/Cargo.lock", peer / "requirements.txt"]
        return {str(p.relative_to(peer)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    before = inventory()
    native_before = hashlib.sha256(args.native.read_bytes()).hexdigest()
    from control_scenario import ControlScenario
    scenario = ControlScenario(args, archived_version=2)
    try:
        scenario.run()
        schedules = []
        for target, active in [(4, 1), (5, 1), (6, 2), (7, 2)]:
            label = "target-" + str(target)
            # Dropping the committed output and its process models cancellation
            # of host dispatch, not rollback or transport-level cancellation.
            initial = scenario.advance(active, label + "-cancelled", target)
            scenario.native_call(label + "-native-reopen", 12, expected=b"reopened")
            scenario.require(scenario.advance(active, label + "-resumed", target) == initial,
                             "dispatch cancellation changed output")
            seen, dropped, duplicated, pending = {}, set(), set(), deque()
            for attempt in range(32):
                step = scenario.advance(active, f"{label}-poll-{attempt}", target)
                if step[1] is None:
                    break
                pending.append((3 - active, step[1]))
                for delivery in range(8):
                    if not pending:
                        break
                    recipient, wire = pending.popleft()
                    key = (recipient, wire[4:12])
                    if key in seen:
                        scenario.require(seen[key] == wire, "control retry replaced original flight")
                    else:
                        seen[key] = wire
                    if key not in dropped:
                        dropped.add(key)
                        continue
                    if key not in duplicated:
                        duplicated.add(key)
                        pending.appendleft((recipient, wire))
                    reply = scenario.receive(recipient, f"{label}-receive-{attempt}-{delivery}", wire)
                    scenario.require(reply[0] == target, "driver changed requested target")
                    if reply[1] is not None:
                        pending.append((3 - recipient, reply[1]))
                    scenario.require(len(pending) <= 32, "control queue capacity")
            else:
                raise ValueError("bounded control schedule exhausted")
            for role in (1, 2):
                scenario.require(scenario.advance(role, f"{label}-confirmed-{role}", target) == (target, None),
                                 "peer did not confirm exact target")
            expected = 5 if (target % 2 == 1 and active == 2) or (target % 2 == 0 and active == 1) else 4
            scenario.require(len(dropped) == len(duplicated) == expected, "every flight loss/duplicate coverage")
            scenario.inspect(lambda _snapshot, state: scenario.require(
                state.traffic.traffic(target)._sent == state.traffic.traffic(target)._received == 0,
                "dummy application work appeared"))
            schedules.append({"target": target, "active_role": active, "attempts": attempt + 1,
                              "lost_flights": len(dropped), "duplicated_flights": len(duplicated),
                              "dummy_application_messages": 0})
        scenario.final_checks()
        scenario.native_call("close", 3, expected=b"closed")
        scenario.require(scenario.native.process.wait(timeout=5) == 0, "native shutdown")
        scenario.require(before == inventory() and native_before == hashlib.sha256(args.native.read_bytes()).hexdigest(),
                         "source or native executable changed during control run")
        report = {"scope": "Independent persisted local-only control requests and bounded explicit-target driver; control pipe is test orchestration, not a network carrier",
                  "epochs": 7, "schedules": schedules, "checks": scenario.checks,
                  "worker_operations": scenario.driver.operations, "native_commands": scenario.native.commands,
                  "control_steps": scenario.steps, "codec_refusals": scenario.codec_refusals,
                  "process_kills": sum("signal" in r for r in scenario.driver.operations),
                  "archived_version_two_codec_sha256": scenario.old_codec_sha256,
                  "archived_version_two_capture_sha256": hashlib.sha256(Path("research/sdk-alpha1/evidence/20261018-independent-durable-rekey/CAPTURE.zip").read_bytes()).hexdigest(),
                  "source_files": before, "native_sha256": native_before, "sources_unchanged": True,
                  "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
                  "native_process_restart": False, "hardware_power_loss": False,
                  "identity_signing_key_in_session": False, "private_keys_or_images_in_artifact": False}
        (scenario.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"epochs": 7, "worker_operations": len(report["worker_operations"]),
                          "native_commands": len(report["native_commands"]), "process_kills": report["process_kills"],
                          "control_steps": len(report["control_steps"]), "codec_refusals": scenario.codec_refusals}))
    finally:
        scenario.native.close()


if __name__ == "__main__":
    main()
