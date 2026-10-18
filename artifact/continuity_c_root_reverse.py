"""Reverse C traffic and receiver-callback process-loss public readback."""
import re

import rust_sdk_profile as sdk

MARKER = (b"ROOT_C_REVERSE processes=5 receiver_sigkill=1 original_reply_recovered=true "
          b"application_records=1 epoch=1\n")


def verify(read, pid, log, *, session: bytes, outbound: bytes, payload: bytes, darwin: bool, cut_ready: bool = False, windows: bool = False) -> dict:
    def public(name, maximum=128):
        return read("public/traffic/" + name, maximum)

    def number(name, *, root=False):
        wire = read(("public/" if root else "public/traffic/") + name, 8)
        sdk.require(len(wire) == 8, "reverse traffic counter width differs")
        return int.from_bytes(wire, "big")

    marker = MARKER.replace(b'sigkill', b'terminateprocess') if windows else MARKER
    sdk.require(public("reverse-result", 1024) == marker, "reverse traffic scope or completion differs")
    reply = public("reply-message", 32)
    sdk.require(len(reply) == 32 and reply[:16] == (1).to_bytes(8, "big") + bytes(8)
                and reply != outbound and public("reply-received", 32) == reply,
                "reverse message identity or direction differs")
    expected = session + reply + payload
    sdk.require(public("effect-reply-cut") == public("effect-reply-recover")
                == public("application-" + reply.hex()) == expected,
                "reverse callback lost or repeated its original effect")
    sdk.require(number("reply-created-on-recovery") == 0, "reverse recovery created a second host effect")
    pid(number("peer-process-reply-next"))
    sdk.require(log("peer-reply-next.stdout") == reply.hex().encode() + b"\n"
                and log("peer-reply-next.stderr") == b"", "reverse message allocation differs")
    stacks = {}
    for stage in ("cut", "recover"):
        process = pid(number("process-traffic-receive-" + stage, root=True))
        pid(number("peer-process-reply-" + stage))
        if stage == "cut":
            sdk.require(number("cut-receiver") == process, "reverse cut selected another process")
        data = log("root-receive-" + stage + ".stdout")
        ready = re.match(rb"root-listening:([1-9][0-9]*)\n", data)
        sdk.require(ready is not None and int(ready[1]) <= 65535
                    and log("root-receive-" + stage + ".stderr") == b"", "root receiver did not listen")
        wanted = (b"root-cut-ready:receiver\n" if cut_ready else b"") if stage == "cut" else b"root-stage-pass:traffic-receive-recover\n"
        sdk.require(data[ready.end():] == wanted, "root receiver completion differs")
        wanted = b"delivery-unknown-committed\n" if stage == "cut" else b"consumed\n"
        sdk.require(log("peer-reply-" + stage + ".stdout") == wanted
                    and log("peer-reply-" + stage + ".stderr") == b"", "reverse delivery outcome differs")
        if darwin:
            actual = number("stack-traffic-receive-" + stage, root=True)
            configured = number("stack-default-traffic-receive-" + stage, root=True)
            sdk.require(actual > 0 and configured > 0, "reverse default stack observation absent")
            stacks[stage] = {"system_default_bytes": configured, "observed_bytes": actual}
    return {"completed": True, "processes": 5, "receiver_terminateprocess" if windows else "receiver_sigkill": 1,
            "message": reply.hex(), "application_records": 1,
            "original_reply_recovered": True, "epoch": 1,
            "default_thread_stacks": stacks, "release_claim_eligible": False}
