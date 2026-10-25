#!/usr/bin/env python3
"""P/G/P/G/R/P/G and actual peer removal on one original registered session."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys


def continue_roster(f, count, journal, session, native_journal, message, original):
    from shared_account_checks import request_arguments
    from witness_policy_checks import request_approval
    from local_policy_checks import policy_inputs
    from roster_revocation_checks import remove_peer
    from qperiapt_continuity_reference.state_codec import encode, decode
    from qperiapt_continuity_reference.policy_snapshot import base_payload
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    public = f.public / "account"
    witnessed = f.bridge is not None
    stale = os.urandom(32)
    _, stale_approval = request_approval(f, "before-R-P4", 4, 310, stale)
    roster_id = os.urandom(32)
    rargs = (roster_id, (public / "roster-4").read_bytes(), (public / "checkpoint-4").read_bytes())
    if witnessed:
        f.call("R-current-clock", 33, (320).to_bytes(8, "big"), b"witness clock set")
        f.worker("R-under-P-prepare-cut", "roster_prepare", rargs, now=320, cut="session-store:committed:intent")
        held = (f.session_path / "intent").read_bytes()
        proposal = f.value("R-under-P-original-preparation", "roster_prepare", rargs, now=320)
        require((f.session_path / "intent").read_bytes() == held, "R under P resealed target")
        f.call("R-current-policy-approval", 39, proposal + (3).to_bytes(8, "big"), b"Prepared")
        f.bridge.arm("after", 16)
        f.worker("R-under-P-lost-commit", "roster_commit", (roster_id,), now=320, refusal="truncated witness reply")
        require(f.worker("R-under-P-recovered", "roster_recover", (roster_id,), now=320) == "Applied", "original R under P")
    else:
        f.worker("R-under-P-original-cut", "roster_refresh", rargs, now=320, cut="session-store:committed:intent")
        require(f.worker("R-under-P-recovered", "roster_status", (roster_id,), now=320) == "Applied", "original local R under P")
    native = f.call("native-original-R-under-P", 40, (4).to_bytes(8, "big") + (320).to_bytes(8, "big"))
    require(native[:32] == native_journal and native[32:64] == session, "R changed original native owner")
    f.worker("P-approval-before-R-refused", "policy_prepare" if witnessed else "policy_stage",
             (stale, stale_approval, *policy_inputs(f, 4)), now=320,
             refusal="roots approved different original decisions")
    if witnessed: f.call("P3-expired-clock", 33, (330).to_bytes(8, "big"), b"witness clock set")
    f.worker("expired-P-not-extended-by-G", "next_id", now=330,
             refusal="witness current authority denied" if witnessed else "expired or premature authority")
    if witnessed: f.call("P4-live-clock", 33, (340).to_bytes(8, "big"), b"witness clock set")
    operation = os.urandom(32)
    request, approval = request_approval(f, "after-R-P4", 4, 340, operation)
    pargs = (operation, approval, *policy_inputs(f, 4))
    if witnessed:
        proposal = f.value("P4-original-prepare", "policy_prepare", pargs, now=340)
        f.call("P4-independent-witness", 43, proposal + len(approval).to_bytes(2, "big") + approval + request, b"Prepared")
        f.worker("P4-ack-cut", "policy_commit", (operation,), now=340, cut="policy:acknowledged")
        require(f.worker("P4-original-recovery", "policy_recover", (operation,), now=340) == "Applied", "P after R")
    else:
        f.worker("P4-stage", "policy_stage", pargs, now=340)
        f.worker("P4-commit-cut", "policy_commit", (operation,), now=340, cut="session-store:committed:head")
        require(f.worker("P4-original-recovery", "policy_status", (operation,), now=340)["status"] == "Committed", "P after R")
    native = f.call("native-P-after-R", 42, (4).to_bytes(8, "big") + (340).to_bytes(8, "big"))
    require(native[:32] == native_journal and native[32:64] == session, "P after R replaced native owner")
    require(f.worker("historical-R-after-next-P", "roster_status", (roster_id,), now=340) == "Applied",
            "next P erased historical R")
    parent = f.owner()
    try:
        with parent.session(340, transport=f.transport()) as owner:
            with owner._owner._state(operational=False) as (snapshot, state):
                r = state.account_renewal.roster
                record = state.policy_renewal
                require(record.roster_history.target.version == 3 and record.active.target.version == 4
                        and record.encode()[:9] == b"QPIPRC02\x02", "R lost its independent historical proof")
                f.refuses("old-R-proof-cannot-authorize-new-R", lambda: r.check_policy(f.context, record, current=True),
                          "roster policy approval differs")
                f.refuses("R-proof-cannot-be-removed", lambda: encode(replace(state,
                    policy_renewal=replace(record, roster_history=None))), "policy record requires exact roster history")
                f.refuses("R-proof-cannot-be-substituted", lambda: encode(replace(state,
                    account_renewal=replace(state.account_renewal, roster=replace(r, authorization=b"x" * 32)))),
                    "roster policy approval differs")
                f.refuses("policy-envelope-cannot-be-stripped", lambda: decode(base_payload(snapshot.payload), f.context),
                          "roster requires the original independently verified policy")
    finally:
        parent.close()

    if witnessed: f.call("G-after-R-P-clock", 33, (355).to_bytes(8, "big"), b"witness clock set")
    gargs = request_arguments(f, count, "G-after-R-P", 18)
    if witnessed:
        proposal = f.value("G-after-R-P-prepare", "credential_account_prepare_files", gargs, now=355)
        f.call("G-after-R-P-independent-witness", 34, proposal + (4).to_bytes(8, "big"), b"Prepared")
        f.worker("G-after-R-P-head-cut", "credential_commit", (gargs[0],), now=355, cut="session-store:committed:head")
        require(f.worker("G-after-R-P-recovered", "credential_recover", (gargs[0],), now=355) == "Applied", "G after R/P")
    else:
        f.worker("G-after-R-P-stage", "credential_account_stage_files", gargs, now=355)
        f.worker("G-after-R-P-head-cut", "credential_commit", (gargs[0],), now=355, cut="session-store:committed:head")
        require(f.worker("G-after-R-P-recovered", "credential_status", (gargs[0],), now=355)["status"] == "Committed", "G after R/P")
    native = f.call("native-G-after-R-P", 40, (18).to_bytes(8, "big") + (355).to_bytes(8, "big"))
    require(native[:32] == native_journal and native[32:64] == session, "G after R/P changed original native owner")
    f.call("native-composed-original-reopen", 12, expected=b"reopened")
    require(f.worker("historical-R-after-next-P-G", "roster_status", (roster_id,), now=355) == "Applied", "G erased old R")
    require(f.value("original-ciphertext-after-composition", "resume", (message,), now=355) == original,
            "composition changed original ciphertext")
    f.call("native-old-epoch-after-composition", 7, application(b"compose", original), b"original P G session")
    identity = f.value("composed-new-epoch-id", "next_id", now=355)
    new = f.value("composed-new-epoch-send", "send", (identity, b"after composed P G R", b"compose"), now=355)
    f.call("native-composed-new-epoch-decrypt", 7, application(b"compose", new), b"after composed P G R")
    removed = remove_peer(f, message, journal, policy_version=4)
    return {"roster_operation": roster_id.hex(), "final_policy_version": 4, "final_roster_version": 19,
            "final_native_time": 355, "retained_policy_proof_version": 3,
            "refusals": f.refusals, "peer_removal": removed,
            "scope": "Original R under P3 survives P4 and G18, then actual receiving peer removal denies old and fresh traffic."}


def run_profile(args, members, witnessed):
    from policy_credential_checks import scenario
    return scenario(args, members, witnessed, after_credentials=continue_roster)


def run_profiles(args):
    # Each profile owns a distinct journal, native process and bridge. Bound
    # concurrency to two; the caller's existing 900-second whole-command limit
    # and all per-worker/transport deadlines remain unchanged.
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="policy-composition") as pool:
        pending = [pool.submit(run_profile, args, n, w) for n in (3, 32) for w in (False, True)]
        return [result.result() for result in pending]


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    args.output, args.native, args.provider_root = args.output.resolve(), args.native.resolve(), args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    def inventory():
        paths = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")), *sorted(root.glob("*.py")),
                 *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock", root / "requirements.txt"]
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before, native = inventory(), hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": native,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = run_profiles(args)
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "composition inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{k:r[k] for k in ("members", "witnessed", "workers", "process_kills")} for r in report["profiles"]]))


if __name__ == "__main__":
    main()
