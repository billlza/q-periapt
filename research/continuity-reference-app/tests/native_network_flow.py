"""Fresh network bootstrap and bidirectional owned TCP at actual OS time."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import socket
import threading
from native_exchange_fixture import save,b64
from native_network_driver import NativeService,DropResponse
from native_outgoing_driver import Effects
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.connection import Consumption
from qperiapt_continuity_reference.connection_run import Run
from qperiapt_continuity_reference.connection_wire import request_route
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.network_server import Server
from qperiapt_continuity_reference.wire import require


def exercise(client,path,identity,key,root,native_session,outgoing,inputs,journal,run,refusals):
    services=[];observed=[];frames=[];native_records=[];python=None;python_thread=None;python_result={}
    effects=Effects(root/'network-effects.sqlite')

    def carrier(address,label):
        transport=TcpTransport(address);number=0
        def call(request,deadline,cancellation):
            nonlocal number
            number+=1;name=label+'-'+str(number);save(root/(name+'.request'),request)
            reply=transport(request,deadline,cancellation);save(root/(name+'.response'),reply)
            frames.append({'label':name,'kind':request[8],'request_sha256':hashlib.sha256(request).hexdigest(),
                           'response_sha256':hashlib.sha256(reply).hexdigest()})
            return reply
        return call

    def start(label):
        value=NativeService(root,label,native_session,inputs);services.append(value);return value

    def reopen():return EnrollmentClient.open(path,identity,key)

    def outgoing_command(label,action,*,success=True):
        target=root/(label+'.json');save(target,dict(inputs,schema='qperiapt-native-outgoing/1',action=action))
        return run([outgoing,target,b64(session)],label,success=success)

    def delivery(message,body,address):
        return {'operation':'deliver_tcp','message':list(message),'plaintext':list(body),
                'associated_data':list(b'TCP application'),'address':f'{address[0]}:{address[1]}'}

    try:
        first=start('network-service-first')
        with client.connect(carrier(first.address,'tcp-bootstrap'),Run()) as connection:
            session=connection.identity;message=connection.next_id(Run())
            require(connection.deliver(message,b'independent TCP first',b'TCP application',carrier(first.address,'tcp-first'),Run()) is Consumption.CONFIRMED,'fresh TCP delivery')
        observed.append(first.stop());require(observed[-1]['stats']['completed_responses']==3,'fresh native TCP exchange count')
        client.close();client=reopen();second=start('network-service-reopened')
        with client.reopen_connection(Run()) as connection:
            require(connection.identity==session,'service restart changed original session')
            idle=[socket.create_connection(second.address,timeout=2) for _ in range(8)]
            try:
                message=connection.next_id(Run())
                require(connection.deliver(message,b'after idle sockets',b'TCP application',carrier(second.address,'tcp-idle-admission'),Run(2)) is Consumption.CONFIRMED,'idle sockets held all admission slots')
            finally:
                for stream in idle:stream.close()
            lost=connection.next_id(Run());relay=DropResponse(second.address)
            try:connection.deliver(lost,b'lost TCP acknowledgement',b'TCP application',TcpTransport(relay.address),Run(10))
            except (OSError,ValueError):refusals.append('network-independent-lost')
            else:raise ValueError('lost TCP response reported success')
            lost_wire=relay.finish()
        save(root/'tcp-lost.request',lost_wire['request']);save(root/'tcp-lost-upstream.response',lost_wire['response'])
        client=reopen()
        with client.reopen_connection(Run()) as connection:
            require(connection.status(lost)=='Committed','lost TCP ACK inferred success')
            require(connection.resume(lost,b'TCP application',carrier(second.address,'tcp-resume'),Run()) is Consumption.CONFIRMED,'original TCP resume')
            require((root/'tcp-resume-1.request').read_bytes()==lost_wire['request'] and
                    (root/'tcp-resume-1.response').read_bytes()==lost_wire['response'],'original network retry changed')
            done=connection.rekey(1,carrier(second.address,'tcp-control'),Run())
            require(done.epoch==1 and done.exchanges==2,'independent TCP rekey target')
        client.close()

        def receive(frame,invocation):
            kind,routed=request_route(frame);require(kind in (3,4) and routed==session,'wrong original independent network route')
            label='tcp-native-'+str(len(native_records)+1);save(root/(label+'.request'),frame)
            current=reopen()
            try:
                with current.reopen_connection(invocation) as connection:
                    response=(connection.serve_message(frame,effects.commit,invocation) if kind==3 else connection.serve_control(frame,invocation))
                save(root/(label+'.response'),response)
                native_records.append({'label':label,'kind':kind,'request_sha256':hashlib.sha256(frame).hexdigest(),
                                       'response_sha256':hashlib.sha256(response).hexdigest()})
                return response
            finally:current.close()
        python=Server(('127.0.0.1',0),receive)
        def serve():
            try:python_result['stats']=python.serve()
            except BaseException as error:python_result['error']=error
        python_thread=threading.Thread(target=serve);python_thread.start()
        message=bytes(outgoing_command('network-native-next',{'operation':'next'})['message'])
        require(outgoing_command('network-native-first',delivery(message,b'native TCP first',python.address))=={'consumption':'Confirmed'},'native TCP first')
        require(effects.read(session,message)==b'native TCP first','native TCP host effect')
        lost=bytes(outgoing_command('network-native-lost-next',{'operation':'next'})['message']);relay=DropResponse(python.address)
        outgoing_command('network-native-lost',delivery(lost,b'native lost TCP ACK',relay.address),success=False)
        native_lost=relay.finish();save(root/'tcp-native-lost.request',native_lost['request']);save(root/'tcp-native-lost-upstream.response',native_lost['response'])
        require(effects.read(session,lost)==b'native lost TCP ACK','native lost TCP effect missing');calls=effects.calls
        require(outgoing_command('network-native-lost-status',{'operation':'status','message':list(lost)})=={'status':'Committed'},'native lost ACK inferred success')
        require(outgoing_command('network-native-resume',delivery(lost,b'native lost TCP ACK',python.address))=={'consumption':'Confirmed'},'native original TCP retry')
        require(effects.calls==calls and native_records[-1]['request_sha256']==hashlib.sha256(native_lost['request']).hexdigest()
                and native_records[-1]['response_sha256']==hashlib.sha256(native_lost['response']).hexdigest(),'consumed TCP replay repeated effect or changed bytes')
        result=outgoing_command('network-native-rekey',{'operation':'rekey_tcp','target':2,'exchanges':4,
            'address':f'{python.address[0]}:{python.address[1]}'})
        require(result=={'epoch':2,'exchanges':2},'native TCP rekey target')
        message=bytes(outgoing_command('network-native-epoch-next',{'operation':'next'})['message'])
        require(outgoing_command('network-native-epoch-two',delivery(message,b'native TCP epoch two',python.address))=={'consumption':'Confirmed'},'native post-rekey TCP delivery')
        require(effects.read(session,message)==b'native TCP epoch two' and effects.count()==3,'network application effects differ')
        python.close();python_thread.join(timeout=5);require(not python_thread.is_alive(),'independent network service did not stop')
        if 'error' in python_result:raise python_result['error']
        require(python_result['stats']['completed_responses']==6,'independent TCP request count')

        client=reopen()
        with client.reopen_connection(Run()) as connection:
            message=connection.next_id(Run());body=b'independent TCP return after native rekey'
            require(connection.deliver(message,body,b'TCP application',carrier(second.address,'tcp-return'),Run()) is Consumption.CONFIRMED,'TCP return after native rekey')
        run([native_session,'read-inbox',root/'inbox.redb',b64(journal),b64(session),b64(message),root/'tcp-received.bin'],'network-read-delivery')
        require((root/'tcp-received.bin').read_bytes()==body,'native TCP effect readback differs')
        observed.append(second.stop());stats=observed[-1]['stats']
        require(stats['completed_responses']==6 and stats['evicted_incomplete']>=7 and stats['operation_errors']==0,'native network admission or completion differs')
        return client,{'schema_version':1,'kind':'qperiapt.native_reference_network','completed':True,
            'services':observed,'independent_service':python_result['stats'],'independent_exchanges':frames,'native_exchanges':native_records,
            'effects':effects.count(),'effect_commit_calls':effects.calls,'confirmed_epoch':2,
            'scope':'Actual-time fresh bootstrap, original service/client reopen, eight idle sockets, actual reply loss and exact retry in both directions, and two rekeys over local TCP. The inner protocol supplies authentication; this is not TLS, cross-host or full lifecycle admission.'}
    finally:
        failures=[]
        if python is not None:
            try:
                python.close()
                if python_thread is not None:
                    python_thread.join(timeout=5);require(not python_thread.is_alive(),'independent receiver remained alive')
            except BaseException as error:failures.append(error)
        for service in services:
            try:
                if service.result is None:service.stop()
            except BaseException as error:failures.append(error)
        try:client.close()
        except BaseException as error:failures.append(error)
        if failures:raise BaseExceptionGroup('network workload cleanup failed',failures)
