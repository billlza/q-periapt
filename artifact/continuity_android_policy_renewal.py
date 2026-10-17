"""Public policy-renewal linkage; executed native consumers verify signatures."""
from pathlib import Path

import continuity_configuration_policy as policy
import continuity_first_configuration as first
import continuity_android_contract as contract
import rust_sdk_profile as sdk

TESTS = {profile: "android_policy_renewal::" + profile for profile in ("fixed", "recoverable")}


def cases(carrier: str) -> tuple:
    sdk.require(carrier in {"local", "signed", "tls"}, "policy renewal carrier")
    steps = [("original.request", "policy-create")]
    if carrier != "local": steps += [("authority-created", "authority-create")]
    steps += [("prepared", "policy-prepare"), ("activated.request", "policy-activate"), ("original.identity", "policy-identity")]
    if carrier != "local": steps += [("policy-peer-unassociated", "policy-peer-unassociated"), ("policy-peer-associated", "authority-peer-associate")]
    steps += [("policy-connected", "policy-peer-connect"), ("policy-message-unknown", "policy-peer-uncertain"),
              ("expired-activation", "policy-activate-expired"), ("expired-identity", "policy-identity"),
              ("policy-request", "policy-request"), ("policy-request-replayed", "policy-request"), ("policy-target-created", "policy-target-create")]
    for label, mode in (("bad-approval", "policy-stage-refused"), ("bad-scope", "policy-stage-scope"), ("cancelled-stage", "policy-stage-cancelled")):
        steps += [(label, mode), (label + "-status", "policy-status"), (label + "-request", "policy-request")]
    steps += [("policy-staged", "policy-stage"), ("policy-stage-replayed", "policy-stage"), ("retained-approvals", "policy-approval")]
    if carrier == "local":
        steps += [("policy-committed", "policy-reconcile"), ("policy-commit-replayed", "policy-reconcile")]
    else:
        steps += [("policy-proposal", "policy-witness-prepare"), ("policy-proposal-replayed", "policy-witness-prepare"),
                  ("policy-proposal-recovered", "policy-witness-recover"), ("policy-reserved", "policy-progress"),
                  ("policy-unknown", "policy-witness-commit-unknown"), ("policy-applied", "policy-witness-reconcile"),
                  ("policy-applied-replayed", "policy-witness-reconcile"), ("policy-close-applied", "policy-witness-close"),
                  ("policy-commit-replayed", "policy-witness-commit-replay"), ("policy-retired", "policy-progress")]
    steps += [("policy-terminal", "policy-status"), ("policy-resolved", "policy-resolve"), ("policy-unselected-refused", "policy-activate-unselected")]
    if carrier != "local": steps += [("policy-unmanaged-refused", "policy-activate-unmanaged")]
    return tuple(steps + [("policy-renewed-identity", "policy-activate-renewed"),
                          ("policy-message-acknowledged", "policy-peer-retry"), ("final.identity", "policy-identity")])


def public(carrier: str) -> tuple:
    outputs = tuple(label for label, _ in cases(carrier))
    files = outputs + tuple(label + "." + suffix for label in outputs for suffix in ("stdout", "stderr"))
    files += ("policy-process-count", "policy-effect-before", "policy-effect-after", "policy-expiry-observation",
              "receiver-policy", "receiver-policy-adopted", "receiver-target-created.stdout", "receiver-target-created.stderr")
    names = ("enrollment-root", "enrollment-intent", "family", "trusted-account", "trusted-roster-version", "trusted-roster-digest",
             "grant-certificate", "grant-roster", "policy-root", "protocol-policy", "policy-version", "policy-digest", "witness-carrier",
             "renewal-request", "renewal-operation", "renewal-approvals", "renewal-statement",
             "policy-target/protocol-policy", "policy-target/policy-version", "policy-target/policy-digest")
    files += tuple("inputs/" + name for name in names)
    if carrier != "local":
        files += ("policy-lost-commit-request", "policy-lost-commit-reply", "policy-historical-transcript")
        files += tuple("inputs/" + name for name in ("renewal-proposal", "authority-id", "authority-application", "authority-checkpoint", "witness-id", "witness-public"))
    return files


def verify_execution(stdout: bytes, directory: Path, profile: str) -> dict:
    sdk.require(profile in TESTS, "policy renewal trust profile")
    text = stdout.decode(); lines = text.splitlines()
    contract.verify_single(stdout, TESTS[profile])
    result = {}
    for carrier in ("local", "signed", "tls"):
        count = len(cases(carrier))
        marker = f"qualified policy renewal {carrier}/{profile}: {count} foreign processes; expired P0, independent P2, original identity session message and one effect"
        sdk.require(lines.count(marker) == 1, "policy carrier missing or duplicated")
        result[carrier + "-" + profile] = verify_route(directory, profile, carrier)
    return result


def verify_route(directory: Path, profile: str, carrier: str, *, with_roster: bool = False, with_credential: bool = False) -> dict:
    """Check one completed route; this alone does not qualify the complete profile."""
    sdk.require(profile in TESTS and carrier in {"local", "signed", "tls"}, "policy route scope")
    label = carrier + "-" + profile; base = directory / label
    def read(name): return sdk.snapshot(base / name).data
    steps = cases(carrier); count = len(steps)
    sdk.require(not (with_roster and with_credential), "distinct policy maintenance routes")
    sdk.require(count == (31 if carrier == "local" else 43), "policy process census definition")
    if with_roster: count += 12 if carrier == "local" else 25
    if with_credential: count += 15 if carrier == "local" else 17
    sdk.require(read("policy-process-count") == count.to_bytes(8, "big"), "policy process census differs")
    for name, mode in steps:
        sdk.require(read(name + ".stdout") == f"{profile}:{mode}:passed\n".encode() and read(name + ".stderr") == b"", "policy process outcome missing: " + name)
    prepared = read("prepared"); identity = read("original.identity")
    sdk.require(len(prepared) == 164 and len(identity) == 64 and identity[32:] == prepared[4:36]
                and all(read(name) == identity for name in ("expired-identity", "policy-renewed-identity", "final.identity")), "policy renewal replaced original identity or journal")
    if carrier == "local": sdk.require(prepared[:4] == (1).to_bytes(4, "big") and prepared[36:] == bytes(128), "local storage preparation changed protection")
    original_data = {"request.bin": read("original.request"), "replayed.bin": read("activated.request"),
                     "intent.bin": read("inputs/enrollment-intent"), "root.bin": read("inputs/enrollment-root"),
                     "session.bin": read("policy-connected"), "unknown.bin": read("policy-message-unknown"),
                     "acknowledged.bin": read("policy-message-acknowledged"), "effect.bin": read("policy-effect-before"), "after-traffic.bin": read("final.identity")}
    if carrier != "local": original_data["genesis.bin"] = prepared
    account, family, identity_until, request_sha = first.verify_original(original_data, after_traffic="identity",
        identity_journal=prepared[4:36] if carrier == "local" else None)
    sdk.require(read("policy-effect-after") == original_data["effect.bin"], "policy retry repeated or replaced business effect")
    operation = verify_renewal(read, carrier, prepared=prepared, account=account, family=family, identity_until=identity_until)
    return {"foreign_processes": count, "operation": operation, "original_request_sha256": request_sha,
                     "original_session": read("policy-connected").hex(), "original_message": read("policy-message-unknown")[32:].hex(),
                     "policy_expired": True, "independent_policy_renewed": True, "business_effects": 1}


def verify_renewal(read, carrier: str, *, prepared: bytes, account: bytes, family: bytes, identity_until: int):
    """Validate one original independently approved renewal, without inventing setup calls."""
    mapping = {"policy-request.bin": "policy-request", "policy-request-replayed.bin": "policy-request-replayed",
               "policy-after-refusal.bin": "bad-approval-request", "policy-refused.bin": "bad-approval", "policy-root.bin": "inputs/policy-root",
               "original-policy.bin": "inputs/protocol-policy", "target-policy.bin": "inputs/policy-target/protocol-policy",
               "target-version.bin": "inputs/policy-target/policy-version", "target-digest.bin": "inputs/policy-target/policy-digest",
               "policy-approvals.bin": "inputs/renewal-approvals", "policy-statement.bin": "inputs/renewal-statement",
               "policy-staged.bin": "policy-staged", "policy-stage-replayed.bin": "policy-stage-replayed"}
    if carrier == "local": mapping.update({"policy-committed.bin": "policy-committed", "policy-commit-replayed.bin": "policy-commit-replayed"})
    else: mapping.update({"genesis.bin": "prepared", "policy-proposal.bin": "policy-proposal", "proposal-replayed.bin": "policy-proposal-replayed",
                          "proposal-recovered.bin": "policy-proposal-recovered", "witness-applied.bin": "policy-applied", "witness-reconciled.bin": "policy-applied-replayed"})
    data = {key: read(value) for key, value in mapping.items()}
    operation = policy.verify(data, carrier=carrier, account=account, family=family, byteorder="big")
    raw = data["policy-request.bin"]
    sdk.require(raw[32:64] == prepared[4:36] and read("inputs/renewal-request") == raw
                and read("inputs/renewal-operation") == raw[:32] and read("retained-approvals") == data["policy-approvals.bin"], "policy original request or saved approvals changed")
    for name, code in (("bad-approval", 102), ("bad-scope", 103), ("cancelled-stage", 302)):
        sdk.require(read(name) == code.to_bytes(4, "big") and read(name + "-status") == bytes(160)
                    and read(name + "-request") == raw, "failed staging changed original state")
    committed = (2).to_bytes(4, "big") + data["policy-staged.bin"][4:]
    sdk.require(read("policy-terminal") == committed
                and read("policy-resolved") == (committed if carrier == "local" else (216).to_bytes(4, "big"))
                and read("policy-unselected-refused") == (1).to_bytes(4, "big") and read("policy-target-created") == b"\x01", "policy terminal or current-target admission differs")
    observation = read("policy-expiry-observation"); sdk.require(len(observation) == 32, "policy expiry observation width")
    data.update({"receiver-policy.bin": read("receiver-policy"), "expiry-observation.bin": observation[:16] + read("receiver-policy-adopted"),
                 "expired-activation.bin": read("expired-activation")})
    # The request below is historical scope, not an inferred current authorization.
    policy.verify_expiry_window(data, family=family, identity_until=identity_until, byteorder="big")
    completed, target_until = int.from_bytes(observation[16:24], "big"), int.from_bytes(observation[24:], "big")
    sdk.require(int.from_bytes(observation[8:16], "big") <= completed < target_until
                == int.from_bytes(policy._checkpoint(data["target-policy.bin"], family)[2][56:64], "big"), "policy target was not live through activation")
    sdk.require(read("receiver-target-created.stdout") == b"QPC_CONFIGURATION_POLICY_TARGET\n" and read("receiver-target-created.stderr") == b"", "native counterpart target creation missing")
    if carrier != "local":
        sdk.require(read("policy-unmanaged-refused") == (211).to_bytes(4, "big") and read("policy-unknown") == (218).to_bytes(4, "big")
                    and read("policy-close-applied") == read("policy-commit-replayed") == (2).to_bytes(4, "big"), "witness unknown/Applied or registry requirement changed")
        proposal = data["policy-proposal.bin"]; target = data["target-version.bin"] + data["target-digest.bin"]
        sdk.require(read("inputs/renewal-proposal") == proposal and read("policy-reserved") == (1).to_bytes(4, "big") + bytes(4) + proposal + target
                    and read("policy-retired") == (2).to_bytes(4, "big") + (1).to_bytes(4, "big") + proposal + target, "original proposal retirement changed")
        request, reply = read("policy-lost-commit-request"), read("policy-lost-commit-reply")
        sdk.require(len(request) == 3674 and request[204] == 11 and len(reply) == 3659, "lost policy commit exchange missing")
        trace = read("policy-historical-transcript")
        sdk.require(0 < len(trace) <= 128 * 7334 and len(trace) % 7334 == 0, "policy history transcript bound")
        for offset in range(0, len(trace), 7334):
            sdk.require(trace[offset] == 1 and trace[offset + 205] not in (11, 13), "history dispatched another policy Commit/Close")
    return operation
