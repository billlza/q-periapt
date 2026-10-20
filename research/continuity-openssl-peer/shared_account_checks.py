#!/usr/bin/env python3
"""Registered common-account renewal with actual writes, process cuts and traffic."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def start(f):
    from qperiapt_continuity_reference.wire import require
    require(f.context.devices[0].pin.account == f.context.devices[1].pin.account,
            "fixture did not create one shared account")
    journal = f.value("accept", "registration_accept", now=150)
    genesis = f.value("prepare", "registration_prepare", (str(f.session_path).encode(),), now=150)
    if f.bridge:
        f.call("independent-shared-enrollment", 30, genesis, b"enrolled")
    initial = f.value("initial", "initial", now=150)
    reply = f.call("reply", 4, initial)
    final = f.value("finish", "finish", (reply,), now=150)
    session = f.call("complete", 5, final)
    require(f.value("activate", "activate", now=170) == session, "original shared session")
    f.call("native-activate", 6, expected=session)
    require(f.worker("common-format", "storage_format", now=170) == 9, "common state format")
    return journal, session


def request_arguments(f, count, name, cycle, *, resigned=False, missing=False, different=False, reverse=False):
    from qperiapt_continuity_reference.account_request import AccountRequest
    public = f.public / "account"
    wire = (public / (f"grant-{cycle}-1-resigned" if resigned else f"grant-{cycle}-1")).read_bytes()
    companions = [(public / f"grant-{cycle}-{identity}").read_bytes()
                  for identity in range(2, count + 1)]
    if missing:
        companions.pop()
    if different:
        companions[1] = (public / f"grant-{cycle}-3-other-operation").read_bytes()
    if reverse:
        companions.reverse()
    target = (public / f"checkpoint-{cycle + 1}").read_bytes()
    request = AccountRequest.parse(wire, companions, f.context.devices[0],
                                   f.context.family, f.context.policy_digest, target)
    data = request.encode()
    (f.out / name).write_bytes(data)
    return (request.local.operation, target, name.encode(), hashlib.sha256(data).digest())


def scenario(args, count):
    from registration_fixture import Fixture
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, f"local-{count}", account_members=count)
    try:
        journal, session = start(f)
        original_id = f.value("original-id", "next_id", now=170)
        original = f.value("original-send", "send", (original_id, b"original shared message", b"shared"), now=170)
        reserved = f.value("reserved-id", "next_id", now=170)
        f.worker("reserved-before-expiry", "send", (reserved, b"reserved shared message", b"shared"),
                 now=170, cut="protocol:send-reserved")
        f.worker("expired-original-refused", "next_id", now=210, refusal="expired or premature authority")
        public = f.public / "account"

        def collection(name, cycle, **options):
            return request_arguments(f, count, name, cycle, **options)

        first = collection("complete-first", 1)
        missing = collection("missing-first", 1, missing=True)
        changed = collection("changed-first", 1, different=True)
        retry = collection("resigned-reordered-first", 1, resigned=True, reverse=True)
        before = (f.session_path / "head").read_bytes()
        f.worker("incomplete-account-refused", "credential_account_stage_files", missing,
                 now=210, refusal="account generation, revocation or credential conflict")
        require((f.session_path / "head").read_bytes() == before, "incomplete set changed original state")
        f.worker("account-stage-kill", "credential_account_stage_files", first,
                 now=210, cut="session-store:committed:intent")
        staged_intent = (f.session_path / "intent").read_bytes()
        require(staged_intent[:8] == b"QPREFI01", "original stage intent")
        pending = f.worker("account-stage-recovered", "credential_status", (first[0],), now=210)
        require(pending["status"] == "Pending"
                and (f.session_path / "head").read_bytes() == staged_intent[52:-32],
                "stage recovery changed the original sealed target")
        f.worker("pending-owner-refused", "storage_format", now=210,
                 refusal="account credential renewal remains pending")
        staged_head = (f.session_path / "head").read_bytes()
        require(f.worker("original-semantic-retry", "credential_account_stage_files", retry, now=210) == pending
                and (f.session_path / "head").read_bytes() == staged_head,
                "semantic retry replaced the first collection")
        f.worker("changed-pending-companion-refused", "credential_account_stage_files", changed,
                 now=210, refusal="different original account renewal collection")
        f.worker("shared-single-grant-refused", "credential_stage",
                 (first[0], (public / "grant-1-1").read_bytes(), first[1]), now=210,
                 refusal="shared account requires stage_account")
        f.worker("account-commit-kill", "credential_commit", (first[0],), now=210,
                 cut="session-store:stage-synced:head")
        committed_intent = (f.session_path / "intent").read_bytes()
        file_count = len(list(f.session_path.iterdir()))
        f.worker("same-account-target-recovery-kill", "credential_status", (first[0],), now=210,
                 cut="session-store:stage-synced:head")
        require((f.session_path / "intent").read_bytes() == committed_intent
                and len(list(f.session_path.iterdir())) == file_count,
                "repeated account recovery resealed or grew staging")
        committed = f.worker("account-commit-recovered", "credential_commit", (first[0],), now=210)
        require(committed["status"] == "Committed"
                and (f.session_path / "head").read_bytes() == committed_intent[52:-32],
                "original complete account commit")
        f.worker("changed-committed-companion-refused", "credential_account_stage_files", changed,
                 now=210, refusal="different original account renewal collection")
        f.worker("other-id-cannot-bypass-pending", "resume", (original_id,), now=210,
                 refusal="different reserved operation")
        resumed = f.value("reserved-message-resume", "resume", (reserved,), now=210)
        require(f.value("original-ciphertext-replay", "resume", (original_id,), now=210) == original,
                "account renewal replaced original ciphertext")
        f.call("receive-original", 7, application(b"shared", original), b"original shared message")
        f.call("receive-reserved", 7, application(b"shared", resumed), b"reserved shared message")
        offer = f.value("renewed-rekey-offer", "prepare_rekey_offer", now=210)
        response = f.call("renewed-rekey-response", 14, offer)
        confirmation = f.value("renewed-rekey-final", "accept_rekey_response", (response,), now=210)
        receipt = f.call("renewed-rekey-receipt", 15, confirmation)
        require(f.worker("renewed-rekey-complete", "accept_rekey_receipt", (receipt,), now=210) == 1,
                "original shared session rekey")
        history = f.worker("committed-after-companion-expiry", "credential_expire", (first[0],), now=280)
        require(history == committed, "expiry relabelled a committed collection")
        following = collection("complete-following", 2)
        f.worker("next-original-account-stage", "credential_account_stage_files", following, now=310)
        require(f.worker("prior-account-outcome-retained", "credential_status", (first[0],), now=310) == committed,
                "next pending request erased the prior completion")
        require(f.worker("next-original-account-commit", "credential_commit", (following[0],), now=310)["status"] == "Committed",
                "second complete account commit")
        identity = f.value("new-epoch-id", "next_id", now=310)
        fresh = f.value("new-epoch-send", "send", (identity, b"new shared epoch", b"shared"), now=310)
        f.call("native-receive-new-epoch", 7, application(b"shared", fresh), b"new shared epoch")
        peer = f.worker("common-peer-head", "peer_authority_status", now=310)
        require(peer[0] == following[1].hex() and peer[3] is True, "peer did not use the common current roster")
        last = f.worker("original-registration-after-groups", "registration_status", now=310)
        require(last["journal"] == journal.hex() and last["signing_id"] == f.observations["signing_id"],
                "account renewal changed original enrollment or signing owner")
        report = {"members": count, "journal": journal.hex(), "session": session.hex(),
                  "worker_operations": f.driver.operations, "native_commands": f.native.commands,
                  "process_kills": sum("signal" in row for row in f.driver.operations),
                  "original_ciphertext_sha256": hashlib.sha256(original).hexdigest(),
                  "reserved_ciphertext_sha256": hashlib.sha256(resumed).hexdigest(),
                  "stage_target_sha256": hashlib.sha256(staged_intent[52:-32]).hexdigest(),
                  "commit_target_sha256": hashlib.sha256(committed_intent[52:-32]).hexdigest(),
                  "scope": "Real registered Python owner and native cryptographic peer, common account, two complete renewals and actual SIGKILL. Explicit Python times150/170/210/280/310; native traffic remains170. No bilateral real-time expiry, required-witness renewal or full shared-account roster lifecycle claim."}
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
    report["profiles"] = {str(count): scenario(args, count) for count in (3, 32)}
    require(before == sources(), "source changed during shared account checks")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
