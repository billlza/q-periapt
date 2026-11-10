"""Read original Android renewal outcomes; native execution verifies authorization."""
from pathlib import Path
import continuity_android_witness as witness
import rust_sdk_profile as sdk

TEST = "android_witness::managed_credential_renewal"
CASES = (
    ("credential-peer-unassociated", "credential-peer-unassociated"), ("credential-peer-associated", "authority-peer-associate"),
    ("credential-connected", "credential-peer-connect"), ("credential-uncertain", "credential-peer-uncertain"),
    ("credential-acknowledged", "credential-peer-retry"),
    ("credential-original-identity", "credential-identity"), ("credential-absent", "credential-status"),
    ("credential-refused", "credential-stage-refused"), ("credential-staged", "credential-stage"),
    ("credential-stage-replayed", "credential-stage"), ("credential-proposal", "credential-prepare"),
    ("credential-proposal-replayed", "credential-prepare"), ("credential-closed", "credential-commit-closed"),
    ("credential-unmanaged", "credential-commit-unmanaged"), ("credential-unknown", "credential-commit-unknown"),
    ("credential-recovered", "credential-reconcile"), ("credential-terminal-replayed", "credential-commit-replay"),
    ("credential-activation-unmanaged", "credential-activate-unmanaged"),
    ("credential-current-activation", "credential-activate"), ("credential-renewed-identity", "credential-identity"),
)
PUBLIC = tuple(name for name, _ in CASES) + (
    "credential-refusal-transcript", "credential-history-transcript", "credential-commit-request",
    "credential-commit-reply", "credential-dispatch-observation", "inputs/renewal-version", "inputs/renewal-digest",
    "credential-effect-before", "credential-effect-after", "credential-effect-count",
    "credential-peer-admit.stdout", "credential-peer-admit.stderr",
) + tuple(name + "." + suffix for name, _ in CASES for suffix in ("stdout", "stderr")) + tuple(
    "traffic-credential-" + mode + "." + suffix for mode in ("bootstrap", "crash-after", "message") for suffix in ("stdout", "stderr"))


def verify_execution(stdout: bytes, directory: Path) -> dict:
    records = witness.verify_execution(stdout, directory, managed=True, test=TEST)
    text = stdout.decode().splitlines()
    for label, record in records.items():
        carrier, trust = label.split("-", 1); base = directory / label
        def read(name): return sdk.snapshot(base / name).data
        marker = f"qualified credential renewal {carrier}/{trust}: same identity and journal, original operation, lost committed reply, historical recovery, current authority activation"
        sdk.require(text.count(marker) == 1, "Android credential renewal outcome missing or duplicated")
        marker = f"qualified credential traffic {carrier}/{trust}: original session and message, receiver effect before exit, renewal, exact retry, one business effect"
        sdk.require(text.count(marker) == 1, "Android credential traffic outcome missing or duplicated")
        for name, operation in CASES:
            sdk.require(read(name + ".stderr") == b"" and read(name + ".stdout") == f"{trust}:{operation}:passed\n".encode(),
                        "Android credential process failed or omitted its outcome")
        identity = read("credential-original-identity")
        sdk.require(len(identity) == 64 and any(identity[:32]) and identity[32:].hex() == record["journal"]
                    and all(read(n) == identity for n in ("credential-current-activation", "credential-renewed-identity")),
                    "Android renewal replaced signing identity or journal")
        sdk.require(read("credential-absent") == bytes(116), "Android renewal was not initially absent")
        for name, code in (("credential-refused", 102), ("credential-closed", 202), ("credential-unmanaged", 211),
                           ("credential-unknown", 218), ("credential-activation-unmanaged", 211)):
            sdk.require(read(name) == code.to_bytes(4, "big"), "Android credential refusal changed")
        proposal = read("credential-proposal")
        sdk.require(len(proposal) == 296 and proposal[:8] == b"QPCRNP01" and read("credential-proposal-replayed") == proposal,
                    "Android credential proposal was replaced on reopen")
        operation, statement = proposal[136:168], proposal[168:200]
        sdk.require(any(operation) and any(statement), "Android credential original identity is absent")
        pending = (1).to_bytes(4, "big") + operation + statement + bytes(48)
        sdk.require(read("credential-staged") == pending and read("credential-stage-replayed") == pending,
                    "Android pending renewal changed or claims a terminal checkpoint")
        committed = read("credential-recovered")
        target = read("inputs/renewal-version") + read("inputs/renewal-digest")
        sdk.require(len(committed) == 116 and committed[:68] == (2).to_bytes(4, "big") + operation + statement
                    and committed[68:76] == (2).to_bytes(8, "big") and any(committed[76:108])
                    and len(target) == 40 and committed[68:108] == target
                    and committed[108:] == bytes(8) and read("credential-terminal-replayed") == committed,
                    "Android historical renewal did not recover the original committed target")
        request, reply = read("credential-commit-request"), read("credential-commit-reply")
        sdk.require(len(request) == 3674 and request[204] == 5 and len(reply) == 3659 and reply[204] == 8,
                    "Android lost-reply observation lacks a real Commit/Applied exchange")
        counts = read("credential-dispatch-observation")
        history_count = 0
        for name in ("credential-refusal-transcript", "credential-history-transcript"):
            data = read(name)
            sdk.require(len(data) % 7334 == 0 and len(data) <= 128 * 7334, "Android credential transcript frame bound")
            for start in range(0, len(data), 7334):
                sdk.require(data[start] in (0, 1) and data[start + 205] != 5,
                            "Android refusal or historical query dispatched a new Commit")
            if name == "credential-history-transcript": history_count = len(data) // 7334
        sdk.require(history_count > 0 and counts == (1).to_bytes(4, "big") + history_count.to_bytes(4, "big") + bytes(4),
                    "Android credential commit/replay dispatch count differs")
        session, uncertain = read("credential-connected"), read("credential-uncertain")
        associated = read("credential-peer-associated")
        sdk.require(read("credential-peer-unassociated") == (201).to_bytes(4,"big") and len(associated) == 72
                    and associated[:32] == bytes([134])*32 and associated[32:40] == (1).to_bytes(8,"big") and any(associated[40:]),
                    "Android peer traffic bypassed independent account association")
        sdk.require(len(session) == 32 and any(session) and len(uncertain) == 64 and uncertain[:32] == session and any(uncertain[32:])
                    and read("credential-acknowledged") == uncertain, "Android credential traffic replaced the session or original message")
        effect = read("credential-effect-before")
        sdk.require(effect == uncertain + b"persisted before process exit" and read("credential-effect-after") == effect and read("credential-effect-count") == (1).to_bytes(4,"big")
                    and read("credential-peer-admit.stdout") == b"credential-peer-admitted\n" and read("credential-peer-admit.stderr") == b"",
                    "Android credential traffic changed the business effect or omitted remote grant admission")
        for mode, expected in (("bootstrap", f"served:1:0:0:0\n{session.hex()}\n{'00'*32}\n"),
                               ("crash-after", ""), ("message", f"served:2:0:1:0\n{session.hex()}\n{uncertain[32:].hex()}\n")):
            prefix = "traffic-credential-" + mode
            lines = read(prefix + ".stdout").decode().split("\n",1)
            sdk.require(read(prefix + ".stderr") == b"" and len(lines) == 2 and lines[0].startswith("listening:")
                        and lines[0][10:].isdigit() and 0 < int(lines[0][10:]) <= 65535 and lines[1] == expected,
                        "Android native receiver omitted or changed its original traffic outcome")
        record.update(foreign_processes=record["foreign_processes"] + len(CASES), original_operation=operation.hex(),
                      signing_identity=identity[:32].hex(), credential_target_digest=committed[76:108].hex(),
                      original_session_traffic_qualified=True, original_session=session.hex(), original_message=uncertain[32:].hex())
    return records
