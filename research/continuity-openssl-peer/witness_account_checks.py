#!/usr/bin/env python3
"""Exact complete-account witness targets, lost replies and retained Closed identity."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def scenario(args, count, close_second):
    from registration_fixture import Fixture
    from shared_account_checks import request_arguments, start
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    directory = args.output / ("closed" if close_second else "applied") / str(count)
    directory.mkdir(parents=True)
    selected = argparse.Namespace(**vars(args))
    selected.output = directory
    f = Fixture(selected, "witness", account_members=count)
    try:
        journal, session = start(f)
        f.call("explicit-native-witness-clock", 33, (170).to_bytes(8, "big"), b"witness clock set")
        identity = f.value("original-id", "next_id", now=170)
        original = f.value("original-send", "send", (identity, b"witnessed shared message", b"shared"), now=170)
        first = request_arguments(f, count, "complete-first", 1)
        retry = request_arguments(f, count, "resigned-first", 1, resigned=True, reverse=True)
        changed = request_arguments(f, count, "changed-first", 1, different=True)
        f.worker("complete-account-preparation-kill", "credential_account_prepare_files", first,
                 now=210, cut="renewal:prepared")
        intent = (f.session_path / "intent").read_bytes()
        require(intent[:8] == b"QPRFLI01" and (f.session_path / "authority").read_bytes()[:8] == b"QPRFLC02",
                "complete witness request was not retained")
        proposal = f.value("original-complete-proposal", "credential_account_prepare_files", retry, now=210)
        require((f.session_path / "intent").read_bytes() == intent, "semantic retry resealed witness target")
        f.worker("different-prepared-set-refused", "credential_account_prepare_files", changed,
                 now=210, refusal="conflicting original local renewal")
        f.worker("unapproved-complete-account-refused", "credential_commit", (first[0],),
                 now=210, refusal="renewal not independently prepared")
        f.call("independent-first-account-approval", 34, proposal, b"Prepared")
        f.bridge.arm("after", 5)
        f.worker("lost-actual-account-commit-reply", "credential_commit", (first[0],),
                 now=210, refusal="truncated witness reply")
        require((f.session_path / "intent").read_bytes() == intent, "unknown result replaced original target")
        recovery_time = 210 if close_second else 280
        f.worker("account-terminal-write-kill", "credential_recover", (first[0],),
                 now=recovery_time, cut="renewal:terminal-durable")
        f.call("actual-witness-reopen", 32, expected=b"witness reopened")
        require(f.worker("account-original-applied-recovery", "credential_recover", (first[0],),
                         now=recovery_time) == "Applied", "original complete witness outcome")
        require((f.session_path / "head").read_bytes() == intent[308:-32]
                and not (f.session_path / "intent").exists(), "witness recovery changed the exact target")
        require(f.value("account-proposal-after-retirement", "credential_account_prepare_files", retry,
                        now=recovery_time) == proposal, "ACK cleanup lost original proposal identity")
        f.worker("different-applied-set-refused", "credential_account_prepare_files", changed,
                 now=recovery_time, refusal="conflicting original local renewal")
        require(f.value("original-ciphertext-after-account-commit", "resume", (identity,), now=recovery_time) == original,
                "witnessed account renewal changed original ciphertext")
        f.call("native-original-receive", 7, application(b"shared", original), b"witnessed shared message")
        second = request_arguments(f, count, "complete-second", 2)
        changed_second = request_arguments(f, count, "changed-second", 2, different=True)
        second_time = 250 if close_second else 310
        p2 = f.value("second-complete-proposal", "credential_account_prepare_files", second, now=second_time)
        f.call("independent-second-account-approval", 34, p2, b"Prepared")
        if close_second:
            prior = (f.session_path / "head").read_bytes()
            require(f.worker("close-second-complete-account", "credential_close", (second[0],),
                             now=second_time) == "Closed", "original witness close")
            require((f.session_path / "head").read_bytes() == prior
                    and not (f.session_path / "intent").exists(), "closed account target changed head")
            require(f.value("closed-original-proposal-retry", "credential_account_prepare_files", second,
                            now=second_time) == p2, "closed complete proposal lost after ACK")
            f.worker("changed-closed-set-refused", "credential_account_prepare_files", changed_second,
                     now=second_time, refusal="conflicting original local renewal")
            require(f.worker("closed-original-status", "credential_status", (second[0],),
                             now=second_time) == "Closed", "closed original status changed")
            active_target = first[1]
        else:
            require(f.worker("apply-second-complete-account", "credential_commit", (second[0],),
                             now=second_time) == "Applied", "second complete account apply")
            active_target = second[1]
        # A closed second collection must preserve the first active binding;
        # selecting the closed binding here would incorrectly disable this owner.
        fresh_id = f.value("current-authority-id", "next_id", now=second_time)
        fresh = f.value("current-authority-send", "send", (fresh_id, b"current shared authority", b"shared"),
                        now=second_time)
        f.call("native-current-receive", 7, application(b"shared", fresh), b"current shared authority")
        offer = f.value("current-authority-rekey", "prepare_rekey_offer", now=second_time)
        response = f.call("native-current-rekey-response", 14, offer)
        final = f.value("current-authority-final", "accept_rekey_response", (response,), now=second_time)
        receipt = f.call("native-current-rekey-receipt", 15, final)
        require(f.worker("current-authority-rekey-confirmed", "accept_rekey_receipt", (receipt,),
                         now=second_time) == 1, "shared witness original session rekey")
        peer = f.worker("common-active-peer-head", "peer_authority_status", now=second_time)
        require(peer[0] == active_target.hex() and peer[3] is True, "common witness peer authority differs")
        last = f.worker("same-original-registration", "registration_status", now=second_time)
        require(last["journal"] == journal.hex() and last["signing_id"] == f.observations["signing_id"],
                "shared witness recovery changed original installation")
        report = {"members": count, "second_outcome": "Closed" if close_second else "Applied",
                  "journal": journal.hex(), "session": session.hex(), "worker_operations": f.driver.operations,
                  "native_commands": f.native.commands, "witness_attempts": f.bridge.records,
                  "process_kills": sum("signal" in row for row in f.driver.operations),
                  "original_target_sha256": hashlib.sha256(intent[308:-32]).hexdigest(),
                  "scope": "Actual registered owner, TCP witness approval, lost real Commit reply, SIGKILL, witness reopen, unchanged target and traffic. Independent times210/250/280/310; native traffic and witness clocks remain170. No bilateral real-time expiry, witness-expiry timing or peer-only shared-roster transition claim."}
        (f.out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        return {"workers": len(f.driver.operations), "native_commands": len(f.native.commands),
                "process_kills": report["process_kills"]}
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
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    before = sources()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = {f"{count}-{closed}": scenario(args, count, closed)
                          for count in (3, 32) for closed in (False, True)}
    require(before == sources(), "source changed during witnessed account checks")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
