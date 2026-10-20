#!/usr/bin/env python3
"""Original common-account writes recovered through independent witness approval."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def inspect_history(f, request, cycle, members):
    """Read the declared public history and compare its full account to signed inputs."""
    from qperiapt_continuity_reference.account_state import AccountState
    from qperiapt_continuity_reference.account_record import AccountRecord
    from qperiapt_continuity_reference.pending_recovery_protocol import Proposal
    from qperiapt_continuity_reference.wire import Reader, require
    proposal = Proposal.decode(request[0])
    histories = []
    for view in proposal.check_metadata(request[1]):
        require(view.count(b"QPIRHS02") == 1, "one complete common history required")
        offset = view.index(b"QPIRHS02")
        size = int.from_bytes(view[offset - 8:offset], "big")
        history = view[offset:offset + size]
        r = Reader(history)
        require(r.take(8) == b"QPIRHS02", "common history tag")
        require(r.take(len(f.context.devices[0].pin.root.raw)) == f.context.devices[0].pin.root.raw
                and r.take(32) == f.context.family and r.take(32) == f.context.policy_digest,
                "original common root/family/policy omitted")
        require(r.integer(8) == 2, "both original roles required")
        projected_roles = []
        for role, original in enumerate(f.context.devices):
            require(r.integer(1) == role and r.take(16) == original.pin.device
                    and r.integer(8) == original.pin.generation
                    and r.take(40) == original.pin.checkpoint()
                    and r.take(32) == original.credential
                    and r.take(len(original.key.raw)) == original.key.raw
                    and (r.integer(8), r.integer(8)) == (original.validity.start, original.validity.end),
                    "common projection substituted original role")
            current, start, end = r.take(32), r.integer(8), r.integer(8)
            projected_roles.append((current, start, end))
            require(r.take(r.integer(8)) == original.roster_wire, "original role roster omitted")
            require((start, end) == (original.validity.start, 200 if cycle == 1 else 300),
                    "projected role validity differs")
            if cycle == 1:
                require(current == original.credential, "initial role commitment differs")
        account = AccountState.read(r.take(r.integer(8)), f.context.devices[0].pin,
                                    f.context.family, f.context.policy_digest)
        record = AccountRecord.read(r.take(r.integer(8)), f.context.devices[0],
                                    f.context.family, f.context.policy_digest, account)
        r.finish()
        for role, original in enumerate(f.context.devices):
            current = account.view(original, local=role == 0).current
            require(projected_roles[role] == (current.digest, current.validity.start, current.validity.end),
                    "projected role differs from verified complete account")
        require(account.listing.checkpoint() == (f.public / f"account/checkpoint-{cycle}").read_bytes()
                and len(account.history) == members
                and len(account.renewals) == (0 if cycle == 1 else members),
                "common projection omitted account grants or history")
        if cycle == 1:
            require(record == AccountRecord(), "initial common coordination differs")
        else:
            require(record.completed is not None and record.pending is None and record.expired is None,
                    "committed common coordination omitted")
        histories.append(history)
    require(histories[0] == histories[1], "ordinary write changed account history")
    return proposal


def recover(f, cycle, members, already_applied, ordinary=None):
    from qperiapt_continuity_reference.wire import require, ldh
    now, prior_time = (210, 170) if cycle == 1 else (310, 250)
    prefix = f"cycle-{cycle}"
    f.call(prefix + "-live-witness-clock", 33, prior_time.to_bytes(8, "big"), b"witness clock set")
    if ordinary is None:
        identity = f.value(prefix + "-id", "next_id", now=prior_time)
        action, arguments = "send", (identity, prefix.encode(), b"shared-recovery")
    else:
        action, arguments, identity = ordinary
    f.bridge.arm("after" if already_applied else "before", 2)
    f.worker(prefix + "-write-reply-lost", action, arguments,
             now=prior_time, refusal="truncated witness reply")
    head, intent = (f.session_path / "head").read_bytes(), (f.session_path / "intent").read_bytes()
    f.call(prefix + "-actual-witness-expiry", 33, now.to_bytes(8, "big"), b"witness clock set")
    request = f.pending_request(prefix + "-original", now)
    repeated = f.pending_request(prefix + "-retry", now)
    require(request[:2] == repeated[:2], "retry changed complete recovery request")
    p = inspect_history(f, request, cycle, members)
    require(p.expected.digest == hashlib.sha256(head).digest()
            and p.target.digest == hashlib.sha256(intent[52:-32]).digest(),
            "recovery did not name exact original images")
    f.call(prefix + "-ordinary-endpoint-refuses-privilege", 31, request[2], status=2)
    f.call(prefix + "-signature-is-not-approval", 37, request[2], status=2)
    confirm = f.confirmation_arguments(prefix + "-original")
    if not already_applied:
        f.worker(prefix + "-unconfirmed-is-not-success", "pending_recovery_confirm_files", confirm, now=now,
                 refusal="exact target and original command not confirmed")
        require((f.session_path / "head").read_bytes() == head
                and (f.session_path / "intent").read_bytes() == intent, "failed confirmation mutated state")
        binding = ldh(b"Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1", request[0])
        f.call(prefix + "-independent-three-record-approval", 36, request[0] + request[1],
               binding + (3).to_bytes(8, "big") * 2)
        f.call(prefix + "-independent-completion", 37, request[2], p.target.wire())
        f.call(prefix + "-actual-witness-reopen", 32, expected=b"witness reopened")
        f.call(prefix + "-exact-privileged-retry", 37, repeated[2], p.target.wire())
    attempts = len(f.bridge.records)
    for index, cut in enumerate(("pending-recovery:queried", "session-store:committed:head",
                                 "session-store:removed:intent")):
        f.worker(prefix + "-confirmation-cut-" + str(index), "pending_recovery_confirm_files", confirm,
                 now=now, cut=cut)
    result = f.worker(prefix + "-confirmed", "pending_recovery_confirm_files", confirm, now=now)
    require(result == p.target.wire().hex()
            and f.worker(prefix + "-confirmed-no-intent", "pending_recovery_confirm_files", confirm, now=now) == result,
            "exact confirmed target unavailable after intent cleanup")
    queries = f.bridge.records[attempts:]
    require(queries and all(row["kind"] == 1 for row in queries)
            and (f.session_path / "head").read_bytes() == intent[52:-32]
            and not (f.session_path / "intent").exists(),
            "confirmation resealed, dispatched a mutation or changed target")
    f.worker(prefix + "-recovery-not-activation", "next_id", now=now, refusal="witness current authority denied")
    return identity, len(request[1]), len(queries)


def scenario(args, members, already_applied, *, full=False):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from qperiapt_continuity_reference.wire import require
    directory = args.output / f"{members}-{'full' if full else ('applied' if already_applied else 'unapplied')}"
    directory.mkdir()
    selected = argparse.Namespace(**vars(args)); selected.output = directory
    f = Fixture(selected, "witness", account_members=members)
    try:
        journal, session = start(f)
        filled, ordinary = None, None
        if full:
            from account_capacity_fixture import fill
            from traffic_checks import application
            filled = fill(f)
            f.call("native-actual-full-consumption", 7, application(b"", filled["ack_wire"]), filled["ack_plain"])
            ack = f.call("native-full-consumption-ACK", 10, filled["ack_id"])
            ordinary = "accept_acknowledgement", (ack,), filled["first_id"]
        metadata, queries = [], []
        original = None
        for cycle in (1, 2):
            identity, size, query_count = recover(f, cycle, members, already_applied and cycle == 1,
                                                   ordinary if cycle == 1 else None)
            metadata.append(size); queries.append(query_count)
            now = 210 if cycle == 1 else 310
            grant = request_arguments(f, members, f"complete-grants-{cycle}", cycle)
            proposal = f.value(f"complete-renewal-{cycle}", "credential_account_prepare_files", grant, now=now)
            f.call(f"independent-complete-renewal-{cycle}", 34, proposal, b"Prepared")
            require(f.worker(f"applied-complete-renewal-{cycle}", "credential_commit", (grant[0],), now=now) == "Applied",
                    "complete account renewal after ordinary recovery")
            wire = f.value(f"resume-original-{cycle}", "resume", (identity,), now=now)
            require(f.value(f"replay-original-{cycle}", "resume", (identity,), now=now) == wire,
                    "original reserved ciphertext differs")
            if full and cycle == 1:
                from local_budget_controls import inventory
                require(wire == filled["first_wire"]
                        and f.value("full-retained-last-message", "resume", (filled["last_id"],), now=now) == filled["last_wire"],
                        "full recovery replaced surviving ciphertext")
                parent = f.owner()
                try:
                    with parent.session(now, transport=f.transport()) as owner:
                        with owner._owner._state(operational=False) as (_, state):
                            retained = inventory(state)
                finally:
                    parent.close()
                require(retained["outboxes"] == 122
                        and retained["traffic_bytes"] == filled["traffic_bytes"] - 153 - len(filled["ack_plain"])
                        and retained["epoch_record_hashes"][0] == filled["inventory"]["epoch_record_hashes"][0],
                        "privileged full recovery changed work beyond the original native ACK")
            if original is None:
                original = identity, wire
            else:
                require(f.value("first-original-after-second-cycle", "resume", (original[0],), now=now) == original[1],
                        "second recovery lost original ciphertext")
        status = f.worker("same-original-registration", "registration_status", now=310)
        require(status["journal"] == journal.hex() and status["signing_id"] == f.observations["signing_id"],
                "ordinary recovery replaced original installation")
        require(metadata[1] > metadata[0] and (members != 32 or metadata[1] > 1024 * 1024),
                "renewed complete account history was not exercised")
        report = {"members": members, "already_applied_first": already_applied, "journal": journal.hex(),
                  "full_business_bytes": None if filled is None else filled["traffic_bytes"],
                  "full_business_rows": None if filled is None else filled["rows"],
                  "session": session.hex(), "metadata_bytes": metadata, "query_only_confirmations": queries,
                  "workers": len(f.driver.operations), "native_commands": len(f.native.commands),
                  "process_kills": sum(row.get("signal") == "SIGKILL" for row in f.driver.operations),
                  "original_ciphertext_sha256": hashlib.sha256(original[1]).hexdigest(),
                  "scope": "Actual registered original state and native witness; clock advances170/210/250/310. Native responder enrollment remains original, so no bilateral renewed native traffic claim."}
        (f.out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    args.output, args.native, args.provider_root = args.output.resolve(), args.native.resolve(), args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    paths = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")), *sorted(root.glob("*.py")),
             *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock",
             root / "requirements.txt"]
    def sources():
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before = sources(); args.output.mkdir()
    report = {"source_files": before, "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = [scenario(args, count, applied) for count, applied in ((3, False), (3, True), (32, False))]
    report["profiles"].append(scenario(args, 32, False, full=True))
    require(before == sources(), "source changed during shared pending recovery checks")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
