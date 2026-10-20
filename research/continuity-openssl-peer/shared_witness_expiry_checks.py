#!/usr/bin/env python3
"""A prepared witness target cannot commit after any selected companion expires."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def scenario(args, count):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from qperiapt_continuity_reference.account_request import AccountRequest
    from qperiapt_continuity_reference.wire import require
    directory = args.output / str(count); directory.mkdir()
    selected = argparse.Namespace(**vars(args)); selected.output = directory
    f = Fixture(selected, "witness", account_members=count)
    try:
        journal, session = start(f)
        f.call("witness-original-expiry", 33, (210).to_bytes(8, "big"), b"witness clock set")
        grant = request_arguments(f, count, "complete-selected-group", 1)
        request = AccountRequest.read((f.out / "complete-selected-group").read_bytes(),
                                      f.context.devices[0], f.context.family, f.context.policy_digest)
        f.context.intervals[0].check(275)
        request.local.current(275)
        require(request.local.successor.validity.end == 300 and request.expires_at() == 275
                and sum(g.successor.validity.end == 275 for g in request.companions) == 1,
                "fixture must isolate companion expiry from local or policy expiry")
        changed = request_arguments(f, count, "different-selected-group", 1, different=True)
        before = (f.session_path / "head").read_bytes()
        proposal = f.value("original-group-prepared", "credential_account_prepare_files", grant, now=210)
        intent = (f.session_path / "intent").read_bytes()
        f.call("independent-root-approval", 34, proposal, b"Prepared")
        require(f.worker("actual-prepared-status", "credential_status", (grant[0],), now=210) == "Prepared",
                "group was not independently prepared")
        f.call("witness-companion-expiry", 33, (275).to_bytes(8, "big"), b"witness clock set")
        attempts = len(f.bridge.records)
        f.worker("expired-companion-refuses-new-commit", "credential_commit", (grant[0],),
                 now=275, refusal="expired or premature authority")
        after = f.bridge.records[attempts:]
        require(after and all(row["kind"] == 6 for row in after),
                "expired group dispatched Commit or another mutation")
        require((f.session_path / "head").read_bytes() == before
                and (f.session_path / "intent").read_bytes() == intent
                and f.worker("still-original-prepared", "credential_status", (grant[0],), now=275) == "Prepared",
                "failed expiry admission changed original outcome or bytes")
        require(f.worker("explicit-original-close", "credential_close", (grant[0],), now=275) == "Closed",
                "original expired group could not close")
        require((f.session_path / "head").read_bytes() == before and not (f.session_path / "intent").exists(),
                "closing installed the expired target")
        require(f.value("closed-original-semantic-retry", "credential_account_prepare_files", grant, now=275) == proposal,
                "expiry or cleanup lost original closed request identity")
        f.worker("different-closed-group-refused", "credential_account_prepare_files", changed, now=275,
                 refusal="conflicting original local renewal")
        f.worker("closed-original-is-not-activation", "next_id", now=275, refusal="witness current authority denied")
        status = f.worker("original-registration-retained", "registration_status", now=275)
        require(status["journal"] == journal.hex() and status["signing_id"] == f.observations["signing_id"],
                "closing replaced original installation")
        report = {"members": count, "session": session.hex(), "journal": journal.hex(),
                  "local_expiry": 300, "earliest_companion_expiry": 275, "terminal": "Closed",
                  "expiry_attempt_kinds": [row["kind"] for row in after], "commit_dispatched_after_expiry": False,
                  "original_head_sha256": hashlib.sha256(before).hexdigest(),
                  "original_intent_sha256": hashlib.sha256(intent).hexdigest(),
                  "workers": len(f.driver.operations), "native_commands": len(f.native.commands),
                  "process_kills": sum(row.get("signal") == "SIGKILL" for row in f.driver.operations)}
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
    report["profiles"] = [scenario(args, count) for count in (3, 32)]
    require(before == sources(), "source changed during prepared companion expiry checks")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
