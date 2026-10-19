#!/usr/bin/env python3
"""One independently owned session operation in a new OS process."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
import os
from pathlib import Path
import signal
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-root", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--cut")
    parser.add_argument("--signer", type=Path)
    parser.add_argument("--witness-address")
    args = parser.parse_args()
    sys.path.append(str(Path(__file__).resolve().parent))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from fixture_inputs import load_original
    from qperiapt_continuity_reference.durable import Session
    from qperiapt_continuity_reference.journal import Scope
    from qperiapt_continuity_reference.resolution import ResolutionReport
    from qperiapt_continuity_reference.wire import require
    with args.configuration.open("rb") as stream:
        private = stream.read(129)
    require(len(private) == 128, "private configuration shape")
    key, scope = private[:32], Scope(private[32:64], private[64:96], private[96:])
    # Historical public inputs reconstruct the exact original context. The
    # operation below separately checks its supplied current trusted time.
    witness_pin = None
    if args.witness_address is not None:
        from fixture_inputs import load_witness_pin
        witness_pin = load_witness_pin(args.public)
    with args.request.open("rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, "worker request capacity")
    def unique(items):
        result = {}
        for name, value in items:
            require(name not in result, "duplicate worker field")
            result[name] = value
        return result
    request = json.loads(raw, object_pairs_hook=unique)
    require(type(request) is dict and set(request) == {"action", "now", "arguments"}
            and type(request["now"]) is int and type(request["arguments"]) is list,
            "worker request schema")
    arguments = [bytes.fromhex(x) for x in request["arguments"]]
    action, now = request["action"], request["now"]
    _, _, context = load_original(args.public, scope.context, now, witness_pin=witness_pin)
    allowed = {"initial", "finish", "activate", "next_id", "send", "resume", "receive", "consume",
               "acknowledgement", "accept_acknowledgement", "status", "upgrade_format", "storage_format",
               "acknowledgement_for_epoch", "prepare_rekey_offer", "respond_rekey_offer",
               "accept_rekey_response", "finish_rekey", "accept_rekey_receipt", "rekey_outbox", "rekey_progress",
               "prepare_rekey_request", "respond_rekey_request", "rekey_request_status",
               "advance_rekey_control", "receive_rekey_control", "start_rekey_control", "replay_rekey_control",
               "begin_closed_epoch_resolution", "acknowledge_closed_epoch_resolution", "closed_epoch_resolution_status",
               "admit_peer_credential_renewal", "admit_peer_roster", "peer_authority_status"}
    renewal_actions = {"local_renewal_prepare", "local_renewal_status", "local_renewal_recover",
                       "local_renewal_commit", "local_renewal_close"}
    local_actions = {"local_credential_stage", "local_credential_status", "local_credential_commit", "local_credential_expire"}
    pending_actions = {"pending_recovery_request_files", "pending_recovery_confirm_files"}
    require(action in (allowed | local_actions) or (witness_pin is not None and
            action in ({"witness_provision", "witness_genesis"} | renewal_actions | pending_actions)), "unknown session action")
    def observe(stage):
        if stage == args.cut:
            print(json.dumps({"pid": os.getpid(), "stage": stage}), flush=True)
            signal.pause()
            raise RuntimeError("killed session worker unexpectedly resumed")
    if action in local_actions:
        from local_renewal_actions import run_local
        result = run_local(action, arguments, now, args.root, scope, key, context, observe)
        print(json.dumps({"result": result}))
        return
    if witness_pin is not None:
        from qperiapt_continuity_reference.witness import Client, TcpTransport
        from qperiapt_continuity_reference.witness_session import WitnessSession
        from signing_fixture import read
        signer = read(args.signer)
        if action in ("witness_provision", "witness_genesis"):
            require(not arguments, "genesis action arguments")
            if action == "witness_provision":
                genesis = WitnessSession.provision(args.root, scope, key, context, signer, now, observe)
            else:
                genesis = WitnessSession.recover_genesis(args.root, scope, key, context, observe)
            print(json.dumps({"result": genesis.wire().hex()}))
            return
        host, port = args.witness_address.rsplit(":", 1)
        client = Client(witness_pin, context.witness.subject(scope.identity), signer, TcpTransport((host, int(port))))
        if action in pending_actions:
            from pending_recovery_actions import run
            result = run(action, arguments, args.request.parent, args.root, scope, key, context, client, observe)
            print(json.dumps({"result": result}))
            return
        if action in renewal_actions:
            from local_renewal_actions import run
            result = run(action, arguments, now, args.root, scope, key, context, client, observe)
            print(json.dumps({"result": result.hex() if isinstance(result, bytes) else result}))
            return
        owner = WitnessSession.open(args.root, scope, key, context, client=client, observer=observe)
    else:
        owner = Session.open(args.root, scope, key, context, observer=observe)
    try:
        if action in ("begin_closed_epoch_resolution", "acknowledge_closed_epoch_resolution", "closed_epoch_resolution_status"):
            require(arguments and len(arguments[0]) == 8, "resolution epoch argument")
            arguments[0] = int.from_bytes(arguments[0], "big")
        if action in ("status", "rekey_progress", "storage_format", "rekey_request_status", "closed_epoch_resolution_status", "peer_authority_status"):
            result = getattr(owner, action)(*arguments)
        elif action in ("prepare_rekey_offer", "respond_rekey_offer", "accept_rekey_response", "finish_rekey",
                        "prepare_rekey_request", "respond_rekey_request", "advance_rekey_control",
                        "receive_rekey_control", "start_rekey_control"):
            from signing_fixture import read
            signer = read(args.signer) if args.signer is not None else None
            if action in ("advance_rekey_control", "start_rekey_control"):
                require(len(arguments) == 1 and len(arguments[0]) == 8, "control target argument")
                arguments = [int.from_bytes(arguments[0], "big")]
            result = getattr(owner, action)(*arguments, signer=signer, now=now)
        else:
            if action in ("rekey_outbox", "acknowledgement_for_epoch"):
                require(all(len(value) == 8 for value in arguments), "integer argument size")
                arguments = [int.from_bytes(value, "big") for value in arguments]
            result = getattr(owner, action)(*arguments, now=now)
        if isinstance(result, ResolutionReport):
            result = result.public_record()
        elif isinstance(result, bytes):
            result = result.hex()
        elif isinstance(result, tuple):
            result = [value.hex() if isinstance(value, bytes) else value for value in result]
        require(type(result) in (str, int, list, dict), "worker output schema")
        print(json.dumps({"result": result}))
    finally:
        owner.close()


if __name__ == "__main__":
    main()
