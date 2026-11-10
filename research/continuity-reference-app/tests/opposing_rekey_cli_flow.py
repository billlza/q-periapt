"""Actual opposing control traffic, with both initial requests in flight."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import json
import subprocess
import threading
from cryptography.exceptions import InvalidSignature
from native_exchange_fixture import save,b64
from native_network_driver import NativeService
from independent_inbound_cli import Receiver
from qperiapt_continuity_reference.connection_run import Run,Cancelled
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.network_server import Server
from qperiapt_continuity_reference.wire import require


def exercise(command,call,root,native,outgoing,inputs,session,journal,client_id,run,commands):
    services=[];relays=[];threads=[];workers=[];frames=[];relay_stats=[];failures=[]
    def native_args(label,action):
        path=root/(label+'.json');save(path,dict(inputs,schema='qperiapt-native-outgoing/1',action=action))
        return [outgoing,path,session]
    def action(label,value):return run(native_args(label,value),label)
    try:
        peer=NativeService(root,'cli-rekey-native-service',native,inputs);services.append(peer)
        receiver=Receiver(root,'cli-rekey-independent-service',command,session,root/'independent-inbox');services.append(receiver)
        ready=threading.Barrier(2);settled=threading.Barrier(2)
        def handler(address,label):
            count=0
            def handle(frame,invocation):
                nonlocal count
                count+=1;name=label+'-'+str(count);save(root/(name+'.request'),frame)
                # Later flights have different lengths by role. Only the two
                # initial requests must overlap; subsequent traffic runs freely.
                if count==1:ready.wait(timeout=10)
                error=None;reply=None
                try:reply=TcpTransport(address)(frame,invocation.deadline,invocation.cancellation)
                except Exception as value:error=value
                if count==1:settled.wait(timeout=10)
                if error is not None:raise error
                save(root/(name+'.response'),reply)
                frames.append({'label':name,'kind':frame[8],'request_sha256':hashlib.sha256(frame).hexdigest(),
                               'response_sha256':hashlib.sha256(reply).hexdigest()})
                return reply
            return handle
        for address,label in ((peer.address,'cli-rekey-independent-wire'),(receiver.address,'cli-rekey-native-wire')):
            relay=Server(('127.0.0.1',0),handler(address,label));relays.append(relay)
            def serve(value=relay):
                try:relay_stats.append(value.serve())
                except BaseException as error:failures.append(error)
            thread=threading.Thread(target=serve);threads.append(thread);thread.start()
        native_action={'operation':'rekey_tcp','target':3,'exchanges':8,
                       'address':f'{relays[1].address[0]}:{relays[1].address[1]}'}
        arguments=[
            ('cli-rekey-opposing-independent',command+['rekey','--session='+session,'--target','3',
              '--address',relays[0].address[0],str(relays[0].address[1])]),
            ('cli-rekey-opposing-native',native_args('cli-rekey-opposing-native',native_action)),
        ]
        for label,args in arguments:
            with (root/(label+'.stdout')).open('wb') as out,(root/(label+'.stderr')).open('wb') as err:
                workers.append((label,subprocess.Popen([str(v) for v in args],stdout=out,stderr=err)))
        for label,process in workers:
            status=process.wait(timeout=35);commands.append({'label':label,'exit':status})
            require(status==0 and not (root/(label+'.stderr')).read_bytes(),'simultaneous rekey failed: '+label)
        require(json.loads((root/'cli-rekey-opposing-independent.stdout').read_bytes())==
                {'session':session,'epoch':3,'exchanges':2}
                and json.loads((root/'cli-rekey-opposing-native.stdout').read_bytes())==
                {'epoch':3,'exchanges':3},'opposing rekey completion')
        for relay in relays:relay.close()
        for thread in threads:thread.join(timeout=5);require(not thread.is_alive(),'rekey relay not joined')
        if failures:raise BaseExceptionGroup('opposing rekey relay failed',failures)
        require(sorted(row['completed_responses'] for row in relay_stats)==[2,3]
                and all(row['operation_errors']==0 for row in relay_stats),'opposing rekey relay accounting')
        require(call('rekey-repeat-independent',['rekey','--session='+session,'--target','3',
                     '--address',peer.address[0],str(peer.address[1])])==
                {'session':session,'epoch':3,'exchanges':0},'original proposer completion')
        require(action('cli-rekey-repeat-native',{'operation':'rekey_tcp','target':3,'exchanges':8,
                       'address':f'{receiver.address[0]}:{receiver.address[1]}'})==
                {'epoch':3,'exchanges':1},'original receipt redispatch')
        py=call('rekey-data-independent-next',['next','--session='+session])['message']
        body=b'after opposing rekey';save(root/'cli-rekey-body.bin',body)
        require(call('rekey-data-independent-send',['deliver','--session='+session,'--message='+py,
                     '--plaintext',root/'cli-rekey-body.bin','--associated-data',root/'cli-empty.bin',
                     '--address',peer.address[0],str(peer.address[1])])['consumption']=='Confirmed','post-rekey send')
        run([native,'read-inbox',root/'inbox.redb',b64(journal),session,py,root/'cli-rekey-native.bin'],
            'cli-rekey-data-native-read')
        message=action('cli-rekey-data-native-next',{'operation':'next'})['message']
        require(action('cli-rekey-data-native-send',{'operation':'deliver_tcp','message':message,
                       'plaintext':list(body),'associated_data':[],
                       'address':f'{receiver.address[0]}:{receiver.address[1]}'})=={'consumption':'Confirmed'},'post-rekey inbound')
        call('rekey-data-independent-read',['read-inbox','--session='+session,'--message='+b64(bytes(message)),
             '--inbox-directory',root/'independent-inbox','--output',root/'cli-rekey-independent.bin'])
        require((root/'cli-rekey-native.bin').read_bytes()==body
                and (root/'cli-rekey-independent.bin').read_bytes()==body,'post-rekey durable effects')
        phases=phase_refusals(call,root,peer.address,session,client_id)
        native_result=peer.stop();independent_result=receiver.stop()
        require(native_result['stats']['completed_responses']==17 and native_result['stats']['operation_errors']==0
                and independent_result['stats']['completed_responses']==5 and independent_result['stats']['operation_errors']==0,'rekey services accounting')
        return {'target':3,'simultaneous':True,'frames':sorted(frames,key=lambda row:row['label']),
                'relays':relay_stats,'native_service':native_result,'independent_service':independent_result,
                'phase_refusals':phases,'effects':2}
    finally:
        cleanup=[]
        for relay in relays:relay.close()
        for thread in threads:
            thread.join(timeout=5)
            if thread.is_alive():cleanup.append(RuntimeError('rekey relay remains alive'))
        for _label,process in workers:
            if process.poll() is None:process.kill();process.wait(timeout=5)
        for service in services:
            if service.result is None:
                try:service.stop()
                except BaseException as error:cleanup.append(error)
        if cleanup:raise BaseExceptionGroup('opposing rekey cleanup failed',cleanup)


def phase_refusals(call,root,address,session,client_id):
    key=(root/'client-wrap.key').read_bytes();records=[]
    for target,case in enumerate(('wrong-journal','cancelled-reply','tampered-flight','forged-empty'),4):
        invocation=Run();owner=EnrollmentClient.open(root/'client',client_id,key,run=invocation)
        try:
            with owner.reopen_connection(invocation) as connection:
                prepared=connection.prepare_rekey(target,invocation)
                before=connection._child.rekey_progress()
        finally:owner.close()
        reply=TcpTransport(address)(prepared.request,invocation.deadline,invocation.cancellation)
        save(root/('cli-control-phase-'+case+'.request'),prepared.request)
        save(root/('cli-control-phase-'+case+'.response'),reply)
        owner=EnrollmentClient.open(root/'client',client_id,key,run=invocation)
        try:
            with owner.reopen_connection(invocation) as connection:
                changed=replace(prepared,journal=bytes(32)) if case=='wrong-journal' else prepared
                if case=='cancelled-reply':invocation.cancellation.cancel()
                if case=='tampered-flight':reply=reply[:-1]+bytes([reply[-1]^1])
                if case=='forged-empty':
                    from qperiapt_continuity_reference import connection_wire
                    reply=connection_wire.frame(connection_wire.CONTROL_REPLY,b'\0')
                try:connection.complete_rekey(changed,reply,invocation)
                except (ValueError,Cancelled,InvalidSignature) as error:
                    refused=type(error).__name__;records.append({'case':case,'target':target})
                else:raise ValueError('unsafe detached control completion')
        finally:owner.close()
        owner=EnrollmentClient.open(root/'client',client_id,key)
        try:
            with owner.reopen_connection(Run()) as connection:
                after=connection._child.rekey_progress()
                require(after==before,'refused control changed original progress')
        finally:owner.close()
        save(root/('cli-control-phase-'+case+'.progress.json'),
             {'target':target,'before':list(before),'after':list(after),'refused':refused})
        result=call('control-phase-'+case+'-resume',['rekey','--session='+session,'--target',str(target),
                    '--address',address[0],str(address[1])])
        require(result['session']==session and result['epoch']==target,'original control recovery')
    return records
