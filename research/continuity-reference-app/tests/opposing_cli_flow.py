"""Barrier-controlled actual opposing sends; no fabricated carrier response."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import json
import subprocess
import threading
from native_exchange_fixture import save,b64
from native_network_driver import NativeService
from independent_inbound_cli import Receiver
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.connection_run import Run,Cancelled
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.network_server import Server
from qperiapt_continuity_reference.wire import require


def exercise(command,call,root,native,outgoing,inputs,session,journal,client_id,run,commands):
    native_service=None;receiver=None;relays=[];threads=[];workers=[]
    frames=[];relay_results=[];failures=[]
    def native_args(label,action):
        path=root/(label+'.json');save(path,dict(inputs,schema='qperiapt-native-outgoing/1',action=action))
        return [outgoing,path,session]
    try:
        py=call('opposing-next',['next','--session='+session])['message']
        native_message=run(native_args('cli-opposing-native-next',{'operation':'next'}),'cli-opposing-native-next')['message']
        body=b'independent simultaneous delivery';ad=b'opposing original'
        save(root/'cli-opposing-body.bin',body);save(root/'cli-opposing-ad.bin',ad)
        native_service=NativeService(root,'cli-opposing-native-service',native,inputs)
        receiver=Receiver(root,'cli-opposing-independent-service',command,session,root/'independent-inbox')
        ready=threading.Barrier(2);settled=threading.Barrier(2)
        def handler(address,label):
            def handle(frame,invocation):
                save(root/(label+'.request'),frame);ready.wait(timeout=10)
                error=None;reply=None
                try:reply=TcpTransport(address)(frame,invocation.deadline,invocation.cancellation)
                except Exception as value:error=value
                # Keep both senders in their exchanges until both incoming
                # handlers have completed; this reproduces the old lease cycle.
                settled.wait(timeout=10)
                if error is not None:raise error
                save(root/(label+'.response'),reply)
                frames.append({'label':label,'kind':frame[8],'request_sha256':hashlib.sha256(frame).hexdigest(),
                               'response_sha256':hashlib.sha256(reply).hexdigest()})
                return reply
            return handle
        for address,label in [(native_service.address,'cli-opposing-python-wire'),(receiver.address,'cli-opposing-native-wire')]:
            relay=Server(('127.0.0.1',0),handler(address,label));relays.append(relay)
            def serve(value=relay):
                try:relay_results.append(value.serve())
                except BaseException as error:failures.append(error)
            thread=threading.Thread(target=serve);threads.append(thread);thread.start()
        native_action={'operation':'deliver_tcp','message':native_message,'plaintext':list(b'native simultaneous delivery'),
                       'associated_data':list(ad),'address':f'{relays[1].address[0]}:{relays[1].address[1]}'}
        arguments=[
            ('cli-opposing-python',command+['deliver','--session='+session,'--message='+py,'--plaintext',root/'cli-opposing-body.bin',
                '--associated-data',root/'cli-opposing-ad.bin','--address',relays[0].address[0],str(relays[0].address[1])]),
            ('cli-opposing-native',native_args('cli-opposing-native',native_action)),
        ]
        for label,args in arguments:
            with (root/(label+'.stdout')).open('wb') as out,(root/(label+'.stderr')).open('wb') as err:
                workers.append((label,subprocess.Popen([str(v) for v in args],stdout=out,stderr=err)))
        for label,process in workers:
            status=process.wait(timeout=35);commands.append({'label':label,'exit':status})
            require(status==0 and not (root/(label+'.stderr')).read_bytes(),'simultaneous send failed: '+label)
        require(json.loads((root/'cli-opposing-python.stdout').read_bytes())==
                {'session':session,'message':py,'consumption':'Confirmed'}
                and json.loads((root/'cli-opposing-native.stdout').read_bytes())=={'consumption':'Confirmed'},'opposing result')
        require(call('opposing-status',['message-status','--session='+session,'--message='+py])==
                {'session':session,'message':py,'status':'Acknowledged'},'opposing independent status')
        require(run(native_args('cli-opposing-native-status',{'operation':'status','message':native_message}),
                    'cli-opposing-native-status')=={'status':'Acknowledged'},'opposing native status')
        call('opposing-read-independent',['read-inbox','--session='+session,'--message='+b64(bytes(native_message)),
             '--inbox-directory',root/'independent-inbox','--output',root/'cli-opposing-independent.bin'])
        run([native,'read-inbox',root/'inbox.redb',b64(journal),session,py,root/'cli-opposing-native.bin'],'cli-opposing-read-native')
        require((root/'cli-opposing-independent.bin').read_bytes()==b'native simultaneous delivery'
                and (root/'cli-opposing-native.bin').read_bytes()==body,'opposing host effects')
        for relay in relays:relay.close()
        for thread in threads:thread.join(timeout=5);require(not thread.is_alive(),'opposing relay not joined')
        if failures:raise BaseExceptionGroup('opposing relay failed',failures)
        for value in relay_results:require(value['completed_responses']==1 and value['operation_errors']==0,'opposing relay completion')
        phase=phase_refusals(call,root,native_service.address,session,client_id)
        native_result=native_service.stop();independent_result=receiver.stop()
        require(native_result['stats']['completed_responses']==7 and native_result['stats']['operation_errors']==0
                and independent_result['stats']['completed_responses']==1 and independent_result['stats']['operation_errors']==0,'opposing service completion')
        return {'frames':sorted(frames,key=lambda row:row['label']),'relays':relay_results,
                'native_service':native_result,'independent_service':independent_result,'phase_refusals':phase,
                'effects':2,'simultaneous':True}
    finally:
        cleanup=[]
        for relay in relays:relay.close()
        for thread in threads:
            thread.join(timeout=5)
            if thread.is_alive():cleanup.append(RuntimeError('opposing relay remains alive'))
        for _label,process in workers:
            if process.poll() is None:process.kill();process.wait(timeout=5)
        for service in (native_service,receiver):
            if service is not None and service.result is None:
                try:service.stop()
                except BaseException as error:cleanup.append(error)
        if cleanup:raise BaseExceptionGroup('opposing workload cleanup failed',cleanup)


def phase_refusals(call,root,address,session,client_id):
    key=(root/'client-wrap.key').read_bytes();records=[]
    for case in ('wrong-journal','cancelled-reply','tampered-ack'):
        selected=call('phase-'+case+'-next',['next','--session='+session])['message']
        from qperiapt_continuity_reference.enrollment_exchange import encoded
        message=encoded(selected,32,32);invocation=Run()
        owner=EnrollmentClient.open(root/'client',client_id,key)
        try:
            with owner.reopen_connection(invocation) as connection:
                prepared=connection.prepare_delivery(message,b'original phase boundary',b'opposing original',invocation)
        finally:owner.close()
        reply=TcpTransport(address)(prepared.request,invocation.deadline,invocation.cancellation)
        save(root/('cli-phase-'+case+'.request'),prepared.request);save(root/('cli-phase-'+case+'.response'),reply)
        owner=EnrollmentClient.open(root/'client',client_id,key)
        try:
            with owner.reopen_connection(invocation) as connection:
                changed=replace(prepared,journal=bytes(32)) if case=='wrong-journal' else prepared
                if case=='cancelled-reply':invocation.cancellation.cancel()
                if case=='tampered-ack':reply=reply[:-1]+bytes([reply[-1]^1])
                try:connection.complete_delivery(changed,reply,invocation)
                except (ValueError,Cancelled):records.append(case)
                else:raise ValueError('unsafe phase completion was accepted')
        finally:owner.close()
        require(call('phase-'+case+'-status',['message-status','--session='+session,'--message='+selected])==
                {'session':session,'message':selected,'status':'Committed'},'failed completion changed original status')
        require(call('phase-'+case+'-resume',['resume','--session='+session,'--message='+selected,
                '--associated-data',root/'cli-opposing-ad.bin','--address',address[0],str(address[1])])==
                {'session':session,'message':selected,'consumption':'Confirmed'},'phase original retry')
    return records
