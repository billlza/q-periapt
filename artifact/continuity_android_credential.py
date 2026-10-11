"""Read original Android renewal outcomes; native execution verifies authorization."""
from pathlib import Path
import continuity_android_witness as witness
import rust_sdk_profile as sdk

TEST = "android_witness::managed_credential_renewal"
CASES = (
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
    "credential-commit-reply", "credential-dispatch-observation",
) + tuple(name + "." + suffix for name, _ in CASES for suffix in ("stdout", "stderr"))


def verify_execution(stdout: bytes, directory: Path) -> dict:
    records = witness.verify_execution(stdout, directory, managed=True, test=TEST)
    text = stdout.decode().splitlines()
    for label, record in records.items():
        carrier, trust = label.split("-", 1); base = directory / label
        def read(name): return sdk.snapshot(base / name).data
        marker = f"qualified credential renewal {carrier}/{trust}: same identity and journal, original operation, lost committed reply, historical recovery, current authority activation"
        sdk.require(text.count(marker) == 1, "Android credential renewal outcome missing or duplicated")
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
        sdk.require(len(committed) == 116 and committed[:68] == (2).to_bytes(4, "big") + operation + statement
                    and committed[68:76] == (2).to_bytes(8, "big") and any(committed[76:108])
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
        record.update(foreign_processes=record["foreign_processes"] + len(CASES), original_operation=operation.hex(),
                      signing_identity=identity[:32].hex(), credential_target_digest=committed[76:108].hex(),
                      original_session_traffic_qualified=False)
    return records
