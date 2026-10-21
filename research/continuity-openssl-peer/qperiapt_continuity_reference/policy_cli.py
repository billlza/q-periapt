"""Original policy maintenance; account and witness approvals remain external.

An error may follow a durable write. Retain the operation and original store;
recover that operation rather than generating a replacement identity.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
from pathlib import Path
import sys
from .cli_files import export_request, public, read_file
from .session_cli import address, identity


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('provider-root', 'directory', 'key-file'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--timeout', type=float, default=30)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('request', 'stage', 'prepare', 'recover-preparation', 'status', 'commit', 'recover',
                 'close-proposal', 'reconcile-expired'):
        command = commands.add_parser(name)
        command.add_argument('--operation', required=True, help='retained nonzero operation ID, unpadded base64url')
        command.add_argument('--witness-address', nargs=2, metavar=('IP', 'PORT'))
        if name in ('request', 'prepare', 'recover-preparation'):
            command.add_argument('--output', type=Path, required=True)
        if name in ('stage', 'prepare'):
            for field in ('account-approval', 'policy-approval', 'policy-pins', 'policy-materials'):
                command.add_argument('--' + field, type=Path, required=True)
    return parser.parse_args(argv)


def witness_transport(value, run):
    if value is None: return None
    from .witness import TcpTransport
    selected = TcpTransport(address(value))
    def bounded(request, deadline):
        run.check()
        result = selected(request, min(deadline, run.deadline))
        run.check()
        return result
    return bounded


def approval_inputs(args):
    from .policy_renewal_proof import APPROVAL_BYTES
    from .wire import require
    approvals = [read_file(path, APPROVAL_BYTES) for path in (args.account_approval, args.policy_approval)]
    require(all(len(value) == APPROVAL_BYTES for value in approvals), 'policy root approval width')
    wire = b'QPPRNB01' + b''.join(len(value).to_bytes(2, 'big') + value for value in approvals)
    return wire, read_file(args.policy_pins, 16384), read_file(args.policy_materials, 131072)


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
        operation = identity(args.operation)
        witness = witness_transport(args.witness_address, run)
        inputs = approval_inputs(args) if args.command in ('stage', 'prepare') else None
        key = read_file(args.key_file, 32, private=True); require(len(key) == 32, 'original wrapping key width')
        run.check(); owner = EnrollmentClient.open(args.directory, client, key, run=run)
        if args.command == 'request':
            result = owner.policy_renewal_request(operation, run.now(), transport=witness)
        else:
            with owner.policy_renewal(operation, run.now(), transport=witness) as renewal:
                if args.command == 'recover-preparation': result = renewal.preparation()
                elif args.command in ('stage', 'prepare'):
                    result = getattr(renewal, args.command)(*inputs, run.now())
                    if args.command == 'prepare': result = renewal.preparation()
                elif args.command in ('commit', 'reconcile-expired'):
                    result = getattr(renewal, args.command.replace('-', '_'))(run.now())
                else: result = getattr(renewal, args.command.replace('-', '_'))()
        run.check(); closing, owner = owner, None; closing.close(); run.check()
        encoded = json.dumps(result, default=public, separators=(',', ':')).encode() + b'\n'
        if hasattr(args, 'output'): export_request(args.output, encoded)
        run.check()
        print(encoded.decode(), end='')
        return 0
    except KeyboardInterrupt:
        print('Interrupted: retain the original operation and query its exact outcome', file=sys.stderr); return 130
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr); return 1
    finally:
        if owner is not None: owner.close()


if __name__ == '__main__': raise SystemExit(main())
