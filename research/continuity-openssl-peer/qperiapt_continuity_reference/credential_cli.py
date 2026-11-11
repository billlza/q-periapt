"""Original single-device or complete-account credential maintenance; account approval stays external.

Keep the same installation and operation after errors, including output loss.
Required-witness preparation does not authorize a commit at the witness.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
from pathlib import Path
import sys
from .cli_files import export_request, public, read_file
from .policy_cli import witness_transport
from .session_cli import identity


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('provider-root', 'directory', 'key-file'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--timeout', type=float, default=30)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('request', 'prepare', 'prepare-account', 'recover-preparation', 'status', 'commit', 'recover', 'close-proposal', 'reconcile-expired'):
        command = commands.add_parser(name)
        command.add_argument('--operation', required=True)
        command.add_argument('--witness-address', nargs=2, metavar=('IP', 'PORT'))
        if name in ('request', 'prepare', 'prepare-account', 'recover-preparation'):
            command.add_argument('--output', type=Path, required=True)
        if name in ('prepare', 'prepare-account'):
            command.add_argument('--issued', type=Path, required=True)
            command.add_argument('--current', type=Path, required=True, help='independently selected current account root/roster')
        if name == 'prepare-account':
            command.add_argument('--companions', type=Path, required=True, help='explicit complete companion issuer envelope set')
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv); owner = None
    try:
        from .provider import load_provider
        load_provider(args.provider_root)
        from .connection_run import Run
        from .enrollment_client import EnrollmentClient
        from .wire import require
        run = Run(args.timeout)
        client = bytes.fromhex(args.client_id); require(len(client) == 32 and any(client), 'original client identity')
        operation = identity(args.operation); witness = witness_transport(args.witness_address, run)
        preparing = args.command in ('prepare', 'prepare-account')
        issued = read_file(args.issued, 131072) if preparing else None
        current = read_file(args.current, 131072) if preparing else None
        from .storage_budget import MAX_ACCOUNT_REQUEST
        companions = read_file(args.companions, MAX_ACCOUNT_REQUEST * 2) if args.command == 'prepare-account' else None
        key = read_file(args.key_file, 32, private=True); require(len(key) == 32, 'original wrapping key width')
        run.check(); owner = EnrollmentClient.open(args.directory, client, key, run=run)
        if args.command == 'request':
            result = owner.credential_renewal_request(operation, run.now(), transport=witness)
        elif preparing:
            result = owner.prepare_credential_renewal(operation, issued, current, run.now(), transport=witness, companion_grants=companions)
        else:
            with owner.credential_renewal(operation, run.now(), transport=witness) as renewal:
                if args.command == 'recover-preparation': result = renewal.preparation()
                elif args.command in ('commit', 'reconcile-expired'):
                    result = getattr(renewal, args.command.replace('-', '_'))(run.now())
                else: result = getattr(renewal, args.command.replace('-', '_'))()
        run.check(); closing, owner = owner, None; closing.close(); run.check()
        encoded = json.dumps(result, default=public, separators=(',', ':')).encode() + b'\n'
        if hasattr(args, 'output'): export_request(args.output, encoded)
        run.check(); print(encoded.decode(), end=''); return 0
    except KeyboardInterrupt:
        print('Interrupted: retain the original operation and query its exact outcome', file=sys.stderr); return 130
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr); return 1
    finally:
        if owner is not None: owner.close()


if __name__ == '__main__': raise SystemExit(main())
