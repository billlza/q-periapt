"""Link exact pending recovery to independent renewal and actual post-rekey traffic."""
from pathlib import Path
import re

import continuity_android_pending as pending
import continuity_android_policy_renewal as renewal
import continuity_first_configuration as first
from continuity_c_witness import commit
import rust_sdk_profile as sdk

TESTS = pending.CONTINUATION_TESTS
FRESH_PAYLOAD = b"continued after pending recovery"


def cases(carrier: str) -> tuple:
    steps = list(renewal.cases(carrier))
    steps = [("original.identity", "policy-identity")] + steps[steps.index(("expired-activation", "policy-activate-expired")):]
    steps[-1:-1] = [("policy-rekeyed", "policy-peer-rekey"), ("policy-fresh-message", "policy-peer-send")]
    sdk.require(carrier in ("signed", "tls") and len(steps) == 37, "continued renewal process catalog")
    return tuple(steps)


def marker(label: str) -> str:
    return ("qualified pending continuation " + label.replace("-", "/") + ": original recovery, independent policy approval, "
            "original message consumed once, rekey1 and fresh traffic")


def public(label: str) -> tuple:
    sdk.require(label in TESTS, "continued route")
    carrier = label.split("-")[0]
    old_outputs = {name + suffix for name, _ in renewal.cases(carrier) for suffix in ("", ".stdout", ".stderr")}
    shared = tuple(name for name in renewal.public(carrier) if name not in old_outputs and name not in
                   ("policy-process-count", "policy-effect-before", "policy-effect-after"))
    outputs = tuple("continued-" + name + suffix for name, _ in cases(carrier) for suffix in ("", ".stdout", ".stderr"))
    return tuple(dict.fromkeys(pending.public(label.endswith("-applied"), process_loss=True) + outputs + shared + (
        "continued-policy-process-count", "continued-policy-effect-before", "continued-policy-effect-after",
        "continued-policy-fresh-effect", "continued-policy-effect-count") + tuple(
        "traffic-continued-policy-" + mode + "." + suffix for mode in ("message", "rekey", "fresh-message") for suffix in ("stdout", "stderr"))))


def verify_execution(stdout: bytes, directory: Path, label: str, *, batch: bool = False) -> dict:
    sdk.require(label in TESTS, "continued route")
    base_result = pending.verify_execution(stdout, directory, label, batch=batch, continuation=True)[label + "-continuation"]
    sdk.require(stdout.decode().splitlines().count(marker(label)) == 1, "continuation marker missing or duplicated")
    carrier, profile, _ = label.split("-"); base = directory / (label + "-continuation")
    def read(name): return sdk.snapshot(base / name).data
    steps = cases(carrier)
    names = {name for name, _ in steps}
    def policy_read(name):
        if name == "prepared": return read("genesis")
        return read(("continued-" if name in names else "") + name)
    sdk.require(read("continued-policy-process-count") == len(steps).to_bytes(8, "big"), "continued process census")
    for name, mode in steps:
        sdk.require(read("continued-" + name + ".stdout") == f"{profile}:{mode}:passed\n".encode()
                    and read("continued-" + name + ".stderr") == b"", "continued foreign call failed: " + name)
    identity = policy_read("original.identity"); prepared = read("genesis")
    sdk.require(len(identity) == 64 and len(prepared) == 164 and identity[32:] == prepared[4:36]
                and all(policy_read(name) == identity for name in ("expired-identity", "policy-renewed-identity", "final.identity")), "continuation changed original identity")
    data = {"request.bin": read("original.request"), "replayed.bin": read("activated.request"),
            "intent.bin": read("inputs/enrollment-intent"), "root.bin": read("inputs/enrollment-root"), "genesis.bin": prepared,
            "session.bin": read("roster-connected"), "unknown.bin": read("roster-unknown"),
            "acknowledged.bin": policy_read("policy-message-acknowledged"), "effect.bin": read("roster-effect-before"),
            "after-traffic.bin": policy_read("final.identity")}
    account, family, identity_until, request_sha = first.verify_original(data, after_traffic="identity")
    proposal, binding, _ = pending.request(read("pending-before-expiry"))
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", read("inputs/witness-id") + read("inputs/witness-public"))
    sdk.require(proposal[8:40] == authority and proposal[40:136] == prepared[36:132]
                and binding == commit(b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1", proposal), "pending recovery and renewed device use different witness subjects")
    operation = renewal.verify_renewal(policy_read, carrier, prepared=prepared, account=account, family=family, identity_until=identity_until)
    sdk.require(read("continued-policy-effect-before") == read("continued-policy-effect-after") == data["effect.bin"], "original business effect changed")
    fresh = policy_read("policy-fresh-message"); session = data["session.bin"]; original = data["unknown.bin"][32:]
    sdk.require(len(fresh) == 64 and fresh[:32] == session and any(fresh[32:]) and fresh[32:] != original
                and read("continued-policy-fresh-effect") == fresh + FRESH_PAYLOAD
                and read("continued-policy-effect-count") == (2).to_bytes(4, "big")
                and policy_read("policy-rekeyed") == b"\1", "post-rekey traffic or distinct effect missing")
    for mode, tail in [("message", f"served:2:0:1:0\n{session.hex()}\n{original.hex()}\n"),
                       ("rekey", "server-rekey-1\n"), ("fresh-message", f"served:2:0:1:1\n{session.hex()}\n{fresh[32:].hex()}\n")]:
        path = "traffic-continued-policy-" + mode
        head, separator, observed = read(path + ".stdout").partition(b"\n")
        sdk.require(re.fullmatch(rb"listening:[1-9][0-9]{0,4}", head) is not None and separator and observed == tail.encode()
                    and read(path + ".stderr") == b"", "native peer did not confirm continued traffic")
    return {label + "-continuation": {"foreign_processes": base_result["foreign_processes"] + len(steps),
        "pending_recovery_calls": base_result["foreign_processes"], "renewal_and_traffic_calls": len(steps),
        "process_cuts": 2, "original_request_sha256": request_sha, "original_session": session.hex(),
        "original_message": original.hex(), "fresh_message": fresh[32:].hex(), "policy_operation": operation,
        "rekey_epoch": 1, "business_effects": 2, "original_effect_duplicated": False}}
