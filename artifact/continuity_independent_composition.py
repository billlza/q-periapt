"""Qualification of one original P/G/R lifecycle, including actual peer removal."""
from continuity_independent_python import require, _policy_identities, _policy_refusals


def verify_capacity(result: dict) -> None:
    rows = result.get("profiles")
    require(type(rows) is list and len(rows) == 2, "full composition cohort differs")
    refused = ["history-duplicate-active-proof", "history-invalid-discriminator", "history-alias-without-active",
        "history-cannot-expand-business", "R-allocation-cannot-fund-send", "history-full-field-capacity",
        "history-truncated-proof", "history-wrong-journal", "history-allocation-cannot-fund-send"]
    for row, witnessed in zip(rows, (False, True), strict=True):
        require(row["witnessed"] is witnessed, "full composition witness profile differs")
        expected = {"members": 32, "traffic_bytes": 2031616, "rows": 123, "native_trusted_time": 355,
                    "workers": 39 if witnessed else 36, "process_kills": 8 if witnessed else 7}
        require(all(type(row[k]) is int and row[k] == v for k, v in expected.items()), "full composition workload differs")
        _policy_identities(row, ("journal", "native_journal", "session", "original_message_sha256", "original_last_message_sha256"))
        history = row["original_inventory"]
        require(type(history["traffic_bytes"]) is int and history["traffic_bytes"] == 2031616
                and type(history["outboxes"]) is int and history["outboxes"] == 123
                and type(history["epoch_record_hashes"]) is list and len(history["epoch_record_hashes"]) == 2,
                "full composition original business missing")
        for epoch, item in enumerate(history["epoch_record_hashes"]):
            require(type(item) is list and len(item) == 2 and type(item[0]) is int and item[0] == epoch,
                    "full composition epoch inventory differs")
            _policy_identities({"digest": item[1]}, ("digest",))
        require(type(row["roster_payload_bytes"]) is int and row["roster_payload_bytes"] > 2 * 1024**2
                and type(row["roster_intent_bytes"]) is int and row["roster_intent_bytes"] > row["roster_payload_bytes"],
                "full composition exact R target missing")
        _policy_refusals(row, refused, "ValueError")
        continued = row["policy_composition"]
        for name, expected in (("history_policy", 3), ("active_policy", 5), ("prepared_proofs", 2 if witnessed else 3)):
            require(type(continued[name]) is int and continued[name] == expected, "full composition proof disposition differs")
        require(continued["business_unchanged"] is True, "full composition business changed")
        for name in ("pending_bytes", "committed_bytes"):
            require(type(continued[name]) is int and 2 * 1024**2 < continued[name] < 8 * 1024**2,
                    "full composition retained image missing")
        require(continued["pending_bytes"] == continued["committed_bytes"] if witnessed else
                continued["pending_bytes"] > continued["committed_bytes"], "full composition prepared image differs")
        adoptions = continued["adoptions"]
        require(type(adoptions) is list and len(adoptions) == 4, "full composition adoptions missing")
        operations = []
        for event, (version, now) in zip(adoptions, ((2, 190), (3, 250), (4, 340), (5, 355)), strict=True):
            require(type(event["version"]) is int and event["version"] == version
                    and type(event["at"]) is int and event["at"] == now, "full composition adoption differs")
            _policy_identities(event, ("operation",)); operations.append(event["operation"])
        require(len(set(operations)) == 4, "full composition reused a policy operation")


def verify_composition(result: dict) -> None:
    rows = result.get("profiles")
    require(type(rows) is list and len(rows) == 4, "composition cohort differs")
    for row, (members, witnessed) in zip(rows, [(3, False), (3, True), (32, False), (32, True)], strict=True):
        require(type(row["members"]) is int and row["members"] == members
                and row["witnessed"] is witnessed, "composition profile differs")
        for name, value in (("workers", 91 if witnessed else 81), ("process_kills", 15), ("confirmed_epoch", 1)):
            require(type(row[name]) is int and row[name] == value, "composition workload differs: " + name)
        _policy_identities(row, ("journal", "native_journal", "session", "original_wire_sha256"))
        operations = []
        for name, field, expected in (("policies", "version", [(2, 190), (3, 250)]),
                                      ("credentials", "cycle", [(1, 210), (2, 310)])):
            events = row[name]
            require(type(events) is list and len(events) == 2, "composition transitions missing")
            for event, (number, now) in zip(events, expected, strict=True):
                require(type(event[field]) is int and event[field] == number
                        and type(event["at"]) is int and event["at"] == now, "composition transition differs")
                _policy_identities(event, ("operation",))
                operations.append(event["operation"])
        continuation = row["after_credentials"]
        for name, expected in (("final_policy_version", 4), ("final_roster_version", 19),
                               ("final_native_time", 355), ("retained_policy_proof_version", 3)):
            require(type(continuation[name]) is int and continuation[name] == expected,
                    "composition continuation differs: " + name)
        _policy_identities(continuation, ("roster_operation",))
        operations.append(continuation["roster_operation"])
        require(len(set(operations)) == len(operations), "composition reused an operation")
        _policy_refusals(continuation, ["old-R-proof-cannot-authorize-new-R", "R-proof-cannot-be-removed",
            "R-proof-cannot-be-substituted", "policy-envelope-cannot-be-stripped"], "ValueError")
        removal = continuation["peer_removal"]
        require(removal["kind"] == "actual_common_account_peer_removal"
                and type(removal["target_version"]) is int and removal["target_version"] == 19
                and all(removal[k] is True for k in ("positive_native_receive",
                    "same_generation_resurrection_refused", "original_enrollment_retained")),
                "composition actual peer removal differs")
        _policy_identities(removal, ("before_wire_sha256", "after_wire_sha256", "target_sha256"))
        require(removal["before_wire_sha256"] != removal["after_wire_sha256"], "composition reused old peer ciphertext")
        denials = ["removed-peer-denies-next-id", "removed-peer-denies-old-output",
                   "removed-peer-denies-old-input", "removed-peer-denies-fresh-input"]
        require(removal["denied_operations"] == denials, "composition peer refusal coverage differs")
        required = set(denials + ["reservation-remains-exclusive", "P-approval-before-R-refused",
            "expired-P-not-extended-by-G", "root-signed-old-generation-resurrection-refused"])
        for cycle in (1, 2):
            required.update(f"cycle-{cycle}-{case}" for case in ("P-blocks-G", "expired-C-still-denied", "G-blocks-P"))
            if witnessed:
                required.update(f"cycle-{cycle}-{case}" for case in ("lost-G-commit-reply", "lost-G-ACK-reply"))
        if witnessed:
            required.update(("R-under-P-lost-commit", "remove-peer-lost-commit"))
        require(type(row["denied_operations"]) is list and set(row["denied_operations"]) == required
                and len(row["denied_operations"]) == len(required), "composition refusal workload differs")
