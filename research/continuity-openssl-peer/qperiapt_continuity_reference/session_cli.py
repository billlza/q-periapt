"""Original owned session CLI; explicit TCP, no account login or signer export.

Each invocation closes its owner. Errors may follow a commit: retain original
device/session directories, message ID/input or rekey target and reconcile them.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
from pathlib import Path
import sys
from contextlib import contextmanager
from .cli_files import read_file,public


def arguments(argv):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('provider-root','directory','key-file'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--client-id',required=True,help='original 32-byte client ID, hexadecimal')
    parser.add_argument('--timeout',type=float,default=30,help='original invocation deadline, 0 < seconds <= 120')
    commands=parser.add_subparsers(dest='command',required=True)
    prepare=commands.add_parser('prepare',help='admit public publication files into the original accepted client')
    prepare.add_argument('--inputs',type=Path,required=True,help='independently provisioned publication plan JSON')
    for name in ('connect','next','message-status','deliver','resume','rekey','serve','provision-inbox','recover-inbox','read-inbox'):
        command=commands.add_parser(name)
        command.add_argument('--witness-address',nargs=2,metavar=('IP','PORT'),help='explicit required-witness TCP endpoint')
        if name!='connect':command.add_argument('--session',required=True,help='original session ID, unpadded base64url')
        if name in ('connect','deliver','resume','rekey'):
            command.add_argument('--address',nargs=2,required=True,metavar=('IP','PORT'))
        if name in ('message-status','deliver','resume'):command.add_argument('--message',required=True)
        if name in ('deliver','resume'):command.add_argument('--associated-data',type=Path,required=True)
        if name=='deliver':command.add_argument('--plaintext',type=Path,required=True)
        if name=='rekey':
            command.add_argument('--target',type=int,required=True);command.add_argument('--exchanges',type=int,default=8)
        if name in ('serve','provision-inbox','recover-inbox','read-inbox'):
            command.add_argument('--inbox-directory',type=Path,required=True)
        if name=='serve':command.add_argument('--listen',nargs=2,required=True,metavar=('IP','PORT'))
        if name=='read-inbox':
            command.add_argument('--message',required=True);command.add_argument('--output',type=Path,required=True)
    return parser.parse_args(argv)


def address(value,*,listen=False):
    from .network import endpoint
    selected=(value[0],int(value[1]));endpoint(selected,listen=listen);return selected


def identity(value):
    from .enrollment_exchange import encoded
    from .wire import require
    result=encoded(value,32,32);require(any(result),'nonzero original session/message ID');return result


@contextmanager
def opened_connection(args,client_id,session,run,witness):
    from .enrollment_client import EnrollmentClient
    from .wire import require
    key=read_file(args.key_file,32,private=True);require(len(key)==32,'client wrapping key length')
    run.check();owner=EnrollmentClient.open(args.directory,client_id,key)
    try:
        with owner.reopen_connection(run,witness_transport=witness) as connection:
            require(connection.identity==session,'original session identity differs')
            yield connection
    finally:owner.close()


def delivery(args,client_id,session,message,plaintext,ad,transport,run,witness):
    with opened_connection(args,client_id,session,run,witness) as connection:
        prepared=(connection.prepare_delivery(message,plaintext,ad,run) if args.command=='deliver'
                  else connection.prepare_resume(message,ad,run))
    # Both cryptographic owners and their private file leases are closed while
    # the peer processes this already-committed original ciphertext.
    run.check();reply=transport(prepared.request,run.deadline,run.cancellation);run.check()
    with opened_connection(args,client_id,session,run,witness) as connection:
        outcome=connection.complete_delivery(prepared,reply,run)
    run.check()
    return {'session':session,'message':message,'consumption':outcome.value}


def main(argv=None):
    args=arguments(argv);owner=None
    try:
        from .provider import load_provider
        load_provider(args.provider_root)
        from .enrollment_client import EnrollmentClient
        from .connection_run import Run
        from .network import TcpTransport
        from .wire import require,MAX_U64
        run=Run(args.timeout)
        client_id=bytes.fromhex(args.client_id);require(len(client_id)==32 and any(client_id),'original client ID')
        prepared=None;transport=None;witness=None;session=None;message=None;plaintext=None;ad=None
        if args.command=='prepare':
            from .publication_inputs import load
            prepared=load(args.inputs,run.now());run.check()
        else:
            if args.witness_address is not None:
                from .witness import TcpTransport as WitnessTransport
                witness=WitnessTransport(address(args.witness_address))
            if args.command!='connect':session=identity(args.session)
            if hasattr(args,'address'):transport=TcpTransport(address(args.address))
            if hasattr(args,'message'):message=identity(args.message)
            if hasattr(args,'plaintext'):plaintext=read_file(args.plaintext,16384,allow_empty=True)
            if hasattr(args,'associated_data'):ad=read_file(args.associated_data,1024,allow_empty=True)
            if args.command=='rekey':require(0<args.target<MAX_U64 and 1<=args.exchanges<=128,'explicit rekey target/allowance')
        if args.command=='serve':
            from .session_server import serve
            return serve(args,client_id,session,witness,address(args.listen,listen=True),run)
        if args.command in ('provision-inbox','recover-inbox','read-inbox'):
            require(witness is None,'host inbox metadata does not select a witness')
        if args.command in ('deliver','resume'):
            result=delivery(args,client_id,session,message,plaintext,ad,transport,run,witness)
            print(json.dumps(result,default=public));return 0
        key=read_file(args.key_file,32,private=True);require(len(key)==32,'client wrapping key length')
        run.check();owner=EnrollmentClient.open(args.directory,client_id,key)
        if prepared is not None:
            require(owner.status()['operation']==prepared[2],'credential artifact belongs to another original enrollment')
            owner.prepare(prepared[0],prepared[1],run.now());run.check()
            result={'prepared':True,'journal':owner.status()['journal']}
        elif args.command in ('provision-inbox','recover-inbox','read-inbox'):
            from .session_server import inbox_command
            result=inbox_command(args,owner,client_id,key,session,message);run.check()
        else:
            connection=(owner.connect(transport,run,witness_transport=witness) if args.command=='connect' else
                        owner.reopen_connection(run,witness_transport=witness))
            with connection:
                actual=connection.identity
                if session is not None:require(actual==session,'original session identity differs')
                result={'session':actual}
                if args.command=='connect':result['peer_confirmation']='Recorded'
                elif args.command=='next':result['message']=connection.next_id(run)
                elif args.command=='message-status':result.update(message=message,status=connection.status(message))
                elif args.command=='rekey':
                    done=connection.rekey(args.target,transport,run,exchanges=args.exchanges)
                    result.update(epoch=done.epoch,exchanges=done.exchanges)
            run.check()
        closing,owner=owner,None;closing.close()
        print(json.dumps(result,default=public));return 0
    except KeyboardInterrupt:
        print('Interrupted: original operation may have committed; retain and reconcile its original identity',file=sys.stderr);return 130
    except Exception as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);return 1
    finally:
        if owner is not None:owner.close()


if __name__=='__main__':raise SystemExit(main())
