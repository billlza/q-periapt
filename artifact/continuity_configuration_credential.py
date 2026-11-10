"""Public linkage for first-use credential renewal; native execution verifies signatures."""
import sys

import continuity_witnessed_renewal as renewal
import rust_sdk_profile as sdk
from continuity_c_witness import commit
from continuity_roster_renewal import envelope

TEST = "managed_first_credential_renewal_preserves_identity_and_delivery"
SOURCE = frozenset({"credential-renewal.bin", "credential-operation.bin", "credential-statement.bin",
                    "credential-proposal.bin", "target-version.bin", "target-digest.bin",
                    "original-certificate.bin", "original-roster.bin", "renewed-certificate.bin",
                    "renewed-roster.bin", "policy-root.bin", "original-policy.bin",
                    "policy-version.bin", "policy-digest.bin"})
OBSERVED = frozenset({"credential-original-identity", "credential-renewed-identity", "credential-expired",
                      "credential-expired-request", "credential-expiry-observation", "credential-refused",
                      "credential-staged", "credential-stage-replayed", "credential-proposal-replayed",
                      "credential-closed", "credential-unmanaged", "credential-unknown",
                      "credential-commit-request", "credential-commit-reply", "credential-recovered",
                      "credential-terminal-replayed", "credential-activation-unmanaged",
                      "credential-current-activation", "credential-dispatch-observation",
                      "credential-refusal-transcript", "credential-history-transcript"})
COMMANDS = frozenset({"credential-original-identity", "credential-renewed-identity", "credential-expired",
                      "credential-expired-request", "credential-refused", "credential-staged",
                      "credential-stage-replayed", "credential-proposal-replayed", "credential-closed",
                      "credential-unmanaged", "credential-unknown", "credential-recovered",
                      "credential-terminal-replayed", "credential-activation-unmanaged",
                      "credential-current-activation", "credential-peer"})
NAMES = SOURCE | {name + ".bin" for name in OBSERVED} | {
    f"{name}.{extension}" for name in COMMANDS for extension in ("stdout", "stderr")}
MAX_READBACK = 128 * 7334


def marker(language: str, carrier: str, profile: str) -> str:
    return (f"INDEPENDENT_CONFIGURATION_CREDENTIAL_RENEWAL_PASS language={language} carrier={carrier} profile={profile} "
            "original_session=true original_message=true uncertain_before_update=true acknowledged=true effects=1")


def expiry_marker(language: str, carrier: str, profile: str) -> str:
    return (f"INDEPENDENT_CONFIGURATION_EXPIRED_CREDENTIAL_PASS language={language} carrier={carrier} profile={profile} "
            "old_activation_refused=true fresh_request_refused=true")


def _materials(data: dict):
    identity = data["credential-original-identity.bin"]
    sdk.require(len(identity) == 64 and all(any(identity[n:n + 32]) for n in (0, 32))
                and identity == data["credential-renewed-identity.bin"]
                == data["credential-current-activation.bin"] == data["after-traffic.bin"],
                "credential renewal replaced the original signer or journal")
    roster = envelope(data["original-roster.bin"], b"QPROST01", 122)
    alias = {"enrollment-root": "root.bin", "enrollment-intent": "intent.bin",
             "enrollment-request": "request.bin", "enrollment-reopened-request": "replayed.bin",
             "trusted-account": "account", "grant-certificate": "original-certificate.bin",
             "grant-roster": "original-roster.bin", "policy-root": "policy-root.bin",
             "policy-version": "policy-version.bin", "policy-digest": "policy-digest.bin",
             "protocol-policy": "original-policy.bin", "credential-renewal": "credential-renewal.bin",
             "credential-operation": "credential-operation.bin", "credential-statement": "credential-statement.bin",
             "renewal-version": "target-version.bin", "renewal-digest": "target-digest.bin"}
    derived = {"trusted-roster-version": roster[40:48],
               "trusted-roster-digest": commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", roster),
               "witness-subject": data["genesis.bin"][36:132],
               "enrollment-genesis-subject": data["genesis.bin"][36:132]}
    def read(name, maximum=8192):
        value = derived[name] if name in derived else data[alias.get(name, name)]
        sdk.require(len(value) <= maximum, "credential material read bound differs")
        return value
    return renewal.verify_grant_materials(read, "first-credential", (identity[:32], identity[32:]))


def _status(raw: bytes, material, phase: int):
    sdk.require(len(raw) == 120 and raw[:4] == phase.to_bytes(4, sys.byteorder)
                and raw[4:36] == material.operation and raw[36:68] == material.statement
                and raw[68:72] == bytes(4) and raw[112:] == bytes(8), "credential status identity or padding differs")
    expected = bytes(40) if phase == 1 else material.target_version.to_bytes(8, sys.byteorder) + material.target_digest
    sdk.require(raw[72:112] == expected, "credential status target checkpoint differs")


def verify(data: dict, *, account: bytes, family: bytes, identity_until: int) -> tuple[str, dict]:
    material = _materials(data)
    sdk.require(material.original["account"] == account.hex() and material.original["family"] == family.hex(),
                "credential renewal belongs to another first account")
    fields = renewal.grant_fields(data["credential-renewal.bin"])
    sdk.require(fields[3] == data["renewed-certificate.bin"] and fields[5] == data["renewed-roster.bin"],
                "credential renewal exported another target")
    for label, phase in (("credential-staged", 1), ("credential-stage-replayed", 1),
                         ("credential-recovered", 2), ("credential-terminal-replayed", 2)):
        _status(data[label + ".bin"], material, phase)
    for label, code in {"credential-expired": 104, "credential-expired-request": 104,
                        "credential-refused": 102, "credential-closed": 202,
                        "credential-unmanaged": 211, "credential-unknown": 218,
                        "credential-activation-unmanaged": 211}.items():
        sdk.require(data[label + ".bin"] == code.to_bytes(4, sys.byteorder), "credential refusal or unknown result differs")
    observation = data["credential-expiry-observation.bin"]
    sdk.require(len(observation) == 24, "credential expiry observation width differs")
    until, at, policy_until = (int.from_bytes(observation[n:n + 8], "big") for n in (0, 8, 16))
    sdk.require(until == identity_until == material.original["validity"]["until_time"] <= at
                < min(policy_until, material.credential_validity[1], material.roster_validity[1])
                and policy_until == int.from_bytes(material.policy[56:64], "big"),
                "credential expiry did not observe expired original and current independent authority")
    proposal = data["credential-proposal.bin"]
    sdk.require(proposal == data["credential-proposal-replayed.bin"], "credential proposal changed after reopen")
    expected, target, binding = renewal.proposal(proposal, material.authority, material.subject,
                                                  material.operation, material.statement)
    frame, = renewal.bound_exchange_frames(b"\0" + data["credential-commit-request.bin"]
                                          + data["credential-commit-reply.bin"], material.authority, material.subject)
    commit_id = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1",
                       material.authority + material.subject + b"\x05" + binding + bytes(64))
    sdk.require(frame.kind == 5 and frame.operation == b"\x05" + binding + bytes(64)
                and frame.outcome == 8 and frame.observed == target and frame.has_last == 1 and frame.last == commit_id,
                "credential lost reply did not follow the exact applied commit")
    history = data["credential-history-transcript.bin"]
    historical = list(renewal.bound_exchange_frames(history, material.authority, material.subject))
    refused = data["credential-refusal-transcript.bin"]
    refusal = list(renewal.bound_exchange_frames(refused, material.authority, material.subject)) if refused else []
    sdk.require(all(f.kind != 5 and f.wire[0] == 1 for f in refusal + historical),
                "historical recovery or refused admission dispatched a credential commit")
    counts = data["credential-dispatch-observation.bin"]
    sdk.require(counts == (1).to_bytes(4, "big") + len(historical).to_bytes(4, "big") + bytes(4),
                "credential dispatch counts differ from signed readback")
    for label in COMMANDS:
        expected = b"credential-peer-admitted\n" if label == "credential-peer" else b"QPC_CONFIGURATION_CREDENTIAL_OPERATION\n"
        sdk.require(data[label + ".stdout"] == expected and data[label + ".stderr"] == b"",
                    "credential foreign process outcome differs")
    return material.operation.hex(), dict(credential_until=until, observed_at=at, policy_until=policy_until,
                                          new_commits=1, historical_exchanges=len(historical), historical_new_commits=0)
