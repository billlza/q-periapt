"""Public readback of root-bound C traffic after an acknowledged root cutover."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import RECORD_BYTES, transcript
import continuity_c_root_reverse as reverse

STAGES = ("connect", "send-cut", "recover", "rekey", "after-rekey")
SENDERS = ("reject-peer", "authorize-peer", *STAGES)
MARKER = (b"ROOT_C_TRAFFIC sender_processes=7 peer_processes=5 sender_sigkill=1 "
          b"peer_exit_after_effect=77 unknown_peer_refused=201 independent_peer_association=1 "
          b"original_message_recovered=true application_records=2 rekey_epoch=1\n")
PAYLOAD = b"persisted before process exit"


def verify(directory: Path, read, *, authority: bytes, original: bytes, target: bytes, history: bytes,
           previous_pids: list[int], darwin: bool, cut_ready: bool = False) -> dict:
    def public(name, maximum=65536):
        return read("public/traffic/" + name, maximum)

    def number(name):
        wire = public(name, 8)
        sdk.require(len(wire) == 8, "traffic counter width differs")
        return int.from_bytes(wire, "big")

    def root_number(name):
        wire = read("public/" + name, 8)
        sdk.require(len(wire) == 8, "traffic root process width differs")
        return int.from_bytes(wire, "big")

    sdk.require(public("result") == MARKER, "root traffic scope or completion differs")
    session, before, after = (public(name, 32) for name in ("session", "message-before", "message-after"))
    sdk.require(all(len(v) == 32 and any(v) for v in (session, before, after))
                and before[:16] == bytes(16) and after[:16] == (1).to_bytes(8, "big") + bytes(8)
                and before != after, "root traffic changed session/message correlation")
    sdk.require(public("effect-before-recovery", 128) == session + before + PAYLOAD
                and public("effect-recover", 128) == session + before + PAYLOAD
                and public("effect-after-rekey", 128) == session + after + PAYLOAD,
                "root traffic lost or duplicated its original application effect")
    sdk.require(number("unknown-peer-code") == 201 and number("peer-associated-revision") == 1
                and public("peer-application", 32) == bytes([156]) * 32,
                "root traffic omitted independent peer authority admission")
    sdk.require(number("uncertain-code") in (303, 309, 310, 311)
                and number("recovered-status") == number("after-status") == 3
                and number("rekey-epoch") == 1, "root traffic outcome or epoch differs")
    pids, stacks, logs = list(previous_pids), {}, set()

    def pid(value):
        sdk.require(0 < value < 2**32 and value not in pids, "traffic process identity differs")
        pids.append(value)
        return value

    def log(name):
        logs.add(name)
        return read("traffic/" + name, log=True)

    for stage in SENDERS:
        wanted = (b"root-cut-ready:sender\n" if cut_ready else b"") if stage == "send-cut" else f"root-stage-pass:traffic-{stage}\n".encode()
        sdk.require(log("sender-" + stage + ".stdout") == wanted
                    and log("sender-" + stage + ".stderr") == b"", "root traffic sender failed")
        process = pid(root_number("process-traffic-" + stage))
        if stage == "send-cut":
            sdk.require(number("cut-sender") == process, "traffic cut did not select its owning sender")
        if darwin:
            actual = root_number("stack-traffic-" + stage)
            configured = root_number("stack-default-traffic-" + stage)
            sdk.require(actual > 0 and configured > 0, "traffic default pthread observation absent")
            stacks[stage] = {"system_default_bytes": configured, "observed_bytes": actual}
    for stage in STAGES:
        pid(number("peer-process-" + stage))
        data = log("peer-" + stage + ".stdout")
        ready = re.match(rb"listening:([1-9][0-9]*)\n", data)
        sdk.require(ready is not None and int(ready[1]) <= 65535
                    and log("peer-" + stage + ".stderr") == b"", "root traffic peer did not listen")
        if stage == "send-cut":
            wanted = b""
        elif stage == "rekey":
            wanted = b"server-rekey-1\n"
        else:
            kind, calls, created = {"connect": (1, 0, 0), "recover": (2, 1, 0), "after-rekey": (2, 1, 1)}[stage]
            message = bytes(32) if stage == "connect" else before if stage == "recover" else after
            wanted = f"served:{kind}:0:{calls}:{created}\n{session.hex()}\n{message.hex()}\n".encode()
        sdk.require(data[ready.end():] == wanted, "root traffic peer consumption or deduplication differs")
    reverse_result = reverse.verify(read, pid, log, session=session, outbound=after,
                                    payload=PAYLOAD, darwin=darwin, cut_ready=cut_ready)
    sdk.require({p.name for p in (directory / "traffic").glob("*.std*")} == logs,
                "root traffic process log census differs")
    traffic_history = public("witness-transcript", RECORD_BYTES * 4096)
    # Existing target and peer journals have already advanced. Verify every
    # retained record from genesis rather than accepting an arbitrary start head.
    observed = transcript(history + traffic_history, authority,
                          expected_lost_advances=0, expected_lost_queries=1, expected_subjects=4,
                          authority_observations=[(original, 5)] + [(target, 5)] * 15)
    # The reverse message adds sender reserve/commit/ACK and receiver commit/
    # consumption. Replaying either original operation must not add another one.
    sdk.require(observed["logical_advances"] == 60, "root traffic durable transition census differs")
    return {"completed": True, "sender_processes": 7, "peer_processes": 5,
            "sender_sigkill": 1, "peer_exit_after_effect": 77, "application_records": 2,
            "session": session.hex(), "original_message": before.hex(), "after_rekey_message": after.hex(),
            "rekey_epoch": 1, "independent_peer_association": True, "default_thread_stacks": stacks,
            "reverse": reverse_result,
            "traffic_witness_exchanges": len(traffic_history) // RECORD_BYTES,
            "full_history_witness": observed, "release_claim_eligible": False}
