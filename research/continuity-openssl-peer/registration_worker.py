#!/usr/bin/env python3
"""One registered-device operation in a fresh, bounded test worker process."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
import os
from pathlib import Path
import signal
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['provider-root', 'public', 'configuration', 'root', 'request']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cut'); parser.add_argument('--witness-address')
    args = parser.parse_args(); sys.path.append(str(Path(__file__).resolve().parent))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from qperiapt_continuity_reference.registration import Registration
    from qperiapt_continuity_reference.registration_protocol import Intent
    from qperiapt_continuity_reference.registration_inputs import Inputs
    from qperiapt_continuity_reference.registered_owner import SESSION
    from qperiapt_continuity_reference.private_files import private_regular
    from qperiapt_continuity_reference.wire import require
    fd = os.open(args.configuration, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        private_regular(os.fstat(fd))
        with os.fdopen(fd, 'rb', closefd=False) as stream: config = stream.read(2122)
    finally: os.close(fd)
    require(len(config) == 2121, 'registered private configuration shape')
    key, identity, intent = config[:32], config[32:64], Intent.from_trusted(config[64:])
    with args.request.open('rb') as stream: raw = stream.read(65537)
    require(len(raw) <= 65536, 'registration worker request bound')
    def unique(items):
        result = {}
        for name, value in items:
            require(name not in result, 'duplicate registration worker field'); result[name] = value
        return result
    request = json.loads(raw, object_pairs_hook=unique)
    require(type(request) is dict and set(request) == {'action', 'arguments', 'now'}
            and type(request['now']) is int and type(request['arguments']) is list, 'registration worker request schema')
    action, now = request['action'], request['now']; arguments = [bytes.fromhex(x) for x in request['arguments']]
    def observe(stage):
        if stage == args.cut:
            print(json.dumps({'pid': os.getpid(), 'stage': stage}), flush=True); signal.pause()
            raise RuntimeError('killed registration worker unexpectedly resumed')
    transport = None
    if args.witness_address is not None:
        from qperiapt_continuity_reference.witness import TcpTransport
        host, port = args.witness_address.rsplit(':', 1); transport = TcpTransport((host, int(port)))
    owner = (Registration.provision(args.root, identity, key, intent, observer=observe) if action == 'provision' else
             Registration.open(args.root, identity, key, intent, recover_initial=action == 'recover_initial', observer=observe))
    try:
        if action in ('provision', 'recover_initial', 'registration_status'):
            require(not arguments, 'registration observation arguments'); result = owner.status()
        elif action == 'registration_request':
            require(not arguments, 'registration request arguments'); result = owner.request(now)
        elif action in ('registration_accept', 'registration_prepare'):
            from fixture_inputs import inputs, load_witness_pin
            pins, materials = inputs(args.public); witness = load_witness_pin(args.public) if transport is not None else None
            if action == 'registration_accept':
                require(not arguments, 'registration acceptance arguments')
                result = owner.accept(materials.initiator_credential, materials.initiator_roster, pins.initiator,
                                      pins, materials, now, witness_pin=witness)
            else:
                require(len(arguments) == 1, 'registration preparation arguments')
                result = owner.prepare(Path(arguments[0].decode('utf-8')), Inputs(pins, materials, witness), now)
        elif action.startswith('credential_'):
            require(bool(arguments), 'registered renewal operation')
            with owner.credential_renewal(arguments[0], now, transport=transport) as child:
                if action == 'credential_account_stage_files':
                    from account_renewal_actions import stage
                    result = stage(child, arguments, args.request.parent, now)
                elif action == 'credential_account_prepare_files':
                    from account_renewal_actions import prepare
                    result = prepare(child, arguments, args.request.parent, now)
                elif action in ('credential_stage', 'credential_prepare'):
                    require(len(arguments) == 3, 'registered renewal preparation arguments')
                    result = getattr(child, 'stage' if action == 'credential_stage' else 'prepare')(*arguments[1:], now=now)
                elif action in ('credential_commit', 'credential_expire'):
                    require(len(arguments) == 1, 'registered renewal transition arguments')
                    result = getattr(child, 'commit' if action == 'credential_commit' else 'reconcile_expired')(now=now)
                else:
                    require(len(arguments) == 1 and action in ('credential_status', 'credential_recover', 'credential_close'), 'registered renewal action')
                    result = getattr(child, {'credential_status': 'status', 'credential_recover': 'recover', 'credential_close': 'close_proposal'}[action])()
        elif action.startswith('roster_'):
            require(bool(arguments), 'registered original roster operation')
            with owner.roster_refresh(arguments[0], now, transport=transport) as child:
                if action in ('roster_refresh', 'roster_prepare'):
                    require(len(arguments) == 3, 'registered roster preparation arguments')
                    result = getattr(child, 'refresh' if action == 'roster_refresh' else 'prepare')(*arguments[1:], now=now)
                elif action == 'roster_commit':
                    require(len(arguments) == 1, 'registered roster commit arguments')
                    result = child.commit(now)
                else:
                    require(len(arguments) == 1 and action in ('roster_status', 'roster_recover', 'roster_close'),
                            'registered roster action')
                    result = getattr(child, {'roster_status':'status', 'roster_recover':'recover',
                                            'roster_close':'close_proposal'}[action])()
        elif action in ('pending_recovery_request_files', 'pending_recovery_confirm_files'):
            from pending_recovery_actions import exchange_files
            with owner.pending_write_recovery(now, transport=transport) as child:
                result = exchange_files(child, action, arguments, args.request.parent)
        else:
            require(action in SESSION, 'registered session action')
            with owner.session(now, transport=transport) as child:
                if action in ('begin_closed_epoch_resolution', 'acknowledge_closed_epoch_resolution', 'closed_epoch_resolution_status'):
                    require(arguments and len(arguments[0]) == 8, 'registered epoch argument'); arguments[0] = int.from_bytes(arguments[0], 'big')
                if action in ('rekey_outbox', 'acknowledgement_for_epoch', 'advance_rekey_control', 'start_rekey_control'):
                    require(all(len(value) == 8 for value in arguments), 'registered integer argument'); arguments = [int.from_bytes(v, 'big') for v in arguments]
                if action in ('status', 'rekey_progress', 'storage_format', 'rekey_request_status', 'closed_epoch_resolution_status', 'peer_authority_status'):
                    result = getattr(child, action)(*arguments)
                else: result = getattr(child, action)(*arguments, now=now)
        from qperiapt_continuity_reference.resolution import ResolutionReport
        def output(value):
            if isinstance(value, bytes): return value.hex()
            if isinstance(value, ResolutionReport): return value.public_record()
            if isinstance(value, tuple): return [output(v) for v in value]
            if isinstance(value, dict): return {k: output(v) for k, v in value.items()}
            require(value is None or type(value) in (str, int, list), 'registered worker result shape'); return value
        print(json.dumps({'result': output(result)}))
    finally: owner.close()


if __name__ == '__main__': main()
