#!/usr/bin/env python3
"""Original group expiry, cancellation and saturated business storage boundaries."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def materials(f, count, cycle):
    from qperiapt_continuity_reference.account_request import AccountRequest
    public = f.public / "account"
    target = (public / f"checkpoint-{8 if cycle == 8 else cycle + 1}").read_bytes()
    return AccountRequest.parse((public / f"grant-{cycle}-1").read_bytes(),
                                [(public / f"grant-{cycle}-{i}").read_bytes() for i in range(2, count + 1)],
                                f.context.devices[0], f.context.family, f.context.policy_digest, target)


def arguments(request):
    return request.local.wire, tuple(g.wire for g in request.companions), request.local.successor_roster.checkpoint()


def summary(f, details):
    result = dict(details, worker_operations=f.driver.operations, native_commands=f.native.commands,
                  refusals=f.refusals, process_kills=sum(row.get("signal") == "SIGKILL" for row in f.driver.operations))
    (f.out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    return {key: result[key] for key in details} | {"process_kills": result["process_kills"],
                                                  "refusal_cases": len(f.refusals)}


def expiry(args):
    from registration_fixture import Fixture
    from shared_account_checks import start
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, "expiry", account_members=3)
    parent = None
    try:
        journal, session = start(f)
        identity = f.value("original-id", "next_id", now=170)
        wire = f.value("original-send", "send", (identity, b"original group expiry", b""), now=170)
        first = materials(f, 3, 1)

        def observer(stage):
            if stage == "local-credential:staged":
                f.refuses("nested-account-call", parent.status, "operation already in progress")
                parent.close()

        parent = f.owner(observer)
        with parent.credential_renewal(first.local.operation, 210) as child:
            f.refuses("callback-close-withholds-stage", lambda: child.stage_account(*arguments(first), now=210),
                      "closed store directory")
        parent.close()
        parent = None
        require(f.worker("original-stage-survived-close", "credential_status", (first.local.operation,), now=210)["status"] == "Pending",
                "callback close lost committed pending")
        f.worker("before-earliest-expiry", "credential_expire", (first.local.operation,),
                 now=274, refusal="account renewal target is not expired")
        f.worker("expired-companion-prevents-commit", "credential_commit", (first.local.operation,),
                 now=275, refusal="expired or premature authority")
        f.worker("expiry-commit-kill", "credential_expire", (first.local.operation,), now=275,
                 cut="session-store:committed:head")
        expired = f.worker("original-expiry-recovered", "credential_status", (first.local.operation,), now=275)
        require(expired["status"] == "ExpiredUncommitted" and expired["time_floor"] == 275
                and first.local.successor.validity.end == 300 and first.expires_at() == 275,
                "whole collection earliest expiry")
        f.worker("expired-account-output-refused", "resume", (identity,), now=275,
                 refusal="expired uncommitted account renewal")
        following = materials(f, 3, 2)
        parent = f.owner()
        with parent.credential_renewal(following.local.operation, 310) as child:
            f.refuses("uncommitted-target-is-not-predecessor",
                      lambda: child.stage_account(*arguments(following), now=310), "account grant predecessor differs")
        parent.close()
        fresh = materials(f, 3, 8)
        parent = f.owner()
        with parent.credential_renewal(fresh.local.operation, 274) as child:
            f.refuses("account-expiry-floor", lambda: child.stage_account(*arguments(fresh), now=274),
                      "account renewal time precedes durable floor")
        parent.close()
        parent = f.owner()
        with parent.credential_renewal(fresh.local.operation, 280) as child:
            require(child.stage_account(*arguments(fresh), now=280)["status"] == "Pending", "fresh retained-predecessor stage")
        parent.close()
        parent = None
        require(f.worker("abandonment-retained-while-pending", "credential_status", (first.local.operation,), now=280) == expired,
                "new stage erased original expiry observation")
        require(f.worker("fresh-original-predecessor-commit", "credential_commit", (fresh.local.operation,), now=280)["status"] == "Committed",
                "fresh group did not commit")
        require(f.value("original-message-after-expiry-recovery", "resume", (identity,), now=280) == wire,
                "group expiry recovery changed original ciphertext")
        f.call("native-original-expiry-message", 7, application(b"", wire), b"original group expiry")
        status = f.worker("same-original-enrollment", "registration_status", now=280)
        require(status["journal"] == journal.hex() and status["signing_id"] == f.observations["signing_id"],
                "expiry recovery replaced original installation")
        return summary(f, {"session": session.hex(), "earliest_expiry": 275, "local_expiry": 300,
                           "observed_expiry": expired, "original_ciphertext_sha256": hashlib.sha256(wire).hexdigest()})
    finally:
        if parent is not None:
            parent.close()
        f.close()


def codec_controls(f, state, payload):
    from dataclasses import replace
    from qperiapt_continuity_reference.account_record import AccountRecord
    from qperiapt_continuity_reference.state_codec import encode, decode
    from qperiapt_continuity_reference.storage_budget import MAX_SHARED_STATE, MAX_STATE
    from qperiapt_continuity_reference.wire import require
    require(encode(state) == payload, "actual shared snapshot roundtrip")
    for version in (5, 6, 7, 8):
        f.refuses("shared-cannot-downgrade-" + str(version),
                  lambda version=version: encode(replace(state, format_version=version)),
                  "shared account requires snapshot version nine")
    f.refuses("missing-completion-cannot-admit-local-grant",
              lambda: encode(replace(state, account_renewal=AccountRecord())),
              "account local grant lacks its original completion")
    receipt = state.account_renewal.completed
    f.refuses("wrong-complete-collection-binding", lambda: encode(replace(
        state, account_renewal=replace(state.account_renewal, completed=replace(receipt, binding=b"x" * 32)))),
        "account completion differs from the committed collection")
    f.refuses("oversized-common-envelope", lambda: decode(payload + bytes(MAX_SHARED_STATE + 1 - len(payload)), f.context),
              "shared-account snapshot scope or capacity")
    f.refuses("envelope-cannot-expand-business-budget",
              lambda: decode(payload[:8] + (MAX_STATE + 1).to_bytes(4, "big") + payload[12:], f.context),
              "shared-account snapshot field capacity")
    f.refuses("truncated-common-envelope", lambda: decode(payload[:-1], f.context), "truncated")
    f.refuses("trailing-common-envelope", lambda: decode(payload + b"x", f.context), "trailing")


def capacity(args):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from local_budget_controls import inventory
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, "capacity", account_members=32)
    parent = None
    try:
        _, session = start(f)
        from account_capacity_fixture import fill
        filled = fill(f)
        plain, first_id, first_wire = (filled[name] for name in ("plain", "first_id", "first_wire"))
        last_id, last_wire, last_plain = (filled[name] for name in ("last_id", "last_wire", "last_plain"))
        original, cap, rows = (filled[name] for name in ("inventory", "traffic_bytes", "rows"))
        first = request_arguments(f, 32, "full-first", 1)
        f.worker("full-group-stage-kill", "credential_account_stage_files", first, now=210,
                 cut="session-store:committed:intent")
        require(f.worker("full-group-pending-recovered", "credential_status", (first[0],), now=210)["status"] == "Pending",
                "full original group stage")
        f.worker("full-group-commit-kill", "credential_commit", (first[0],), now=210,
                 cut="session-store:committed:head")
        require(f.worker("full-group-committed", "credential_status", (first[0],), now=210)["status"] == "Committed",
                "full original group commit")
        second = request_arguments(f, 32, "full-second", 2)
        f.worker("full-second-group-stage", "credential_account_stage_files", second, now=310)
        large = (f.session_path / "head").stat().st_size
        require(large > 3 * 1024 * 1024, "full group did not exercise extra physical allocation")
        require(f.worker("full-second-group-commit", "credential_commit", (second[0],), now=310)["status"] == "Committed",
                "full second group commit")
        parent = f.owner()
        with parent.session(310) as owner:
            with owner._owner._state(operational=False) as (snapshot, state):
                require(inventory(state) == original, "group renewal changed full business records")
                codec_controls(f, state, snapshot.payload)
            require(owner.resume(first_id, now=310) == first_wire and owner.resume(last_id, now=310) == last_wire,
                    "full group lost old ciphertext")
            f.refuses("group-metadata-cannot-fund-business",
                      lambda: owner.send(owner.next_id(now=310), b"x", b"", now=310), "reserved final traffic capacity")
        parent.close()
        parent = None
        head = (f.session_path / "head").read_bytes()
        f.worker("shared-peer-only-roster-refused", "admit_peer_roster",
                 ((f.public / "account/roster-4").read_bytes(),
                  (f.public / "account/checkpoint-4").read_bytes()),
                 now=310, refusal="shared-account changes require complete account coordination")
        require((f.session_path / "head").read_bytes() == head, "refused peer-only update changed common state")
        f.call("native-full-original-receive", 7, application(b"", first_wire), plain)
        f.call("native-full-last-receive", 7, application(b"", last_wire), last_plain)
        return summary(f, {"session": session.hex(), "members": 32, "traffic_bytes": cap, "rows": rows,
                           "original_inventory": original, "large_pending_image_bytes": large,
                           "original_ciphertext_sha256": hashlib.sha256(first_wire).hexdigest()})
    finally:
        if parent is not None:
            parent.close()
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
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    before = sources()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["expiry"], report["capacity"] = expiry(args), capacity(args)
    require(before == sources(), "source changed during common account boundary checks")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({name: report[name] for name in ("expiry", "capacity")}))


if __name__ == "__main__":
    main()
