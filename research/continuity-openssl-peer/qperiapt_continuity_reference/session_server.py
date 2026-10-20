"""Original-session inbound service and host inbox commands, without bootstrap."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
import json
import signal
from .cli_files import read_file,export_request,public
from .connection_run import Cancellation
from .connection_wire import request_route,MESSAGE,CONTROL
from .enrollment_client import EnrollmentClient
from .mailbox import Mailbox
from .network_server import Server,Limits
from .wire import require


def original(owner,session):
    require(owner.connection_confirmation()==session,'original confirmed inbox session differs')
    journal=owner.status()['journal']
    require(type(journal) is bytes and len(journal)==32 and any(journal),'original inbox journal absent')
    return journal


def separate(client,inbox):
    require(inbox.is_absolute() and '..' not in inbox.parts and client.is_absolute()
            and not inbox.is_relative_to(client) and not client.is_relative_to(inbox),
            'host inbox and client directories must be separate')


def inbox_command(args,owner,client_id,key,session,message):
    separate(args.directory,args.inbox_directory);journal=original(owner,session)
    if args.command=='provision-inbox':
        box=Mailbox.provision(args.inbox_directory,client_id,journal,session,key)
    else:
        box=Mailbox.open(args.inbox_directory,client_id,journal,session,key,recover_initial=args.command=='recover-inbox')
    with box:
        result={'session':session,'journal':journal,'inbox':'Provisioned' if args.command=='provision-inbox' else 'Recovered'}
        if args.command=='read-inbox':
            body=box.delivery(message);export_request(args.output,body)
            result={'session':session,'message':message,'delivery':'Exported','bytes':len(body)}
        return result


@dataclass(frozen=True)
class Configuration:
    directory:Path
    client_id:bytes
    key_file:Path
    inbox_directory:Path
    session:bytes
    witness:Callable[[bytes,float,Cancellation],bytes]|None=None

    @contextmanager
    def open(self,run):
        separate(self.directory,self.inbox_directory)
        key=read_file(self.key_file,32,private=True);require(len(key)==32,'client wrapping key length')
        run.check();owner=EnrollmentClient.open(self.directory,self.client_id,key)
        try:
            journal=original(owner,self.session)
            with Mailbox.open(self.inbox_directory,self.client_id,journal,self.session,key) as box:
                with owner.reopen_connection(run,witness_transport=self.witness) as connection:
                    require(connection.identity==self.session,'original session identity differs')
                    run.check();yield connection,box,journal;run.check()
        finally:owner.close()

    def handle(self,frame,run):
        kind,session=request_route(frame)
        require(kind in (MESSAGE,CONTROL) and session==self.session,'wrong original inbound route')
        with self.open(run) as (connection,box,_journal):
            return connection.serve_message(frame,box.commit,run) if kind==MESSAGE else connection.serve_control(frame,run)


def serve(args,client_id,session,witness,listen,startup):
    configuration=Configuration(args.directory,client_id,args.key_file,args.inbox_directory,session,witness)
    # Validate the real original session and inbox before declaring readiness.
    # Each accepted complete request opens fresh original owners under its own
    # enclosing deadline, so failed input cannot detach a stale long-lived owner.
    with configuration.open(startup) as (_connection,_box,journal):pass
    cancellation=Cancellation()
    listener=Server(listen,configuration.handle,cancellation=cancellation,
                    limits=Limits(read_timeout=min(2,args.timeout),operation_timeout=args.timeout))
    previous={}
    try:
        for number in (signal.SIGINT,signal.SIGTERM):
            previous[number]=signal.signal(number,lambda _signum,_frame:cancellation.cancel())
        print(json.dumps({'service':'Listening','carrier':'QPCXCH01/TCP','address':listener.address,
                          'session':session,'journal':journal},default=public),flush=True)
        stats=listener.serve()
        print(json.dumps({'service':'Stopped','stats':stats}),flush=True)
        return 0
    finally:
        listener.close()
        for number,handler in previous.items():signal.signal(number,handler)
