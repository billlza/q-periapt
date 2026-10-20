"""Separate-process independent CLI with real native effects and lost TCP replies."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import copy
import hashlib
import json
import os
import sys
import threading
from native_exchange_fixture import save,b64
from native_network_driver import NativeService,DropResponse
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.network_server import Server
from qperiapt_continuity_reference.wire import require


def exercise(implementation,provider,client_dir,session_dir,client_id,root,native,outgoing,inputs,journal,original,run):
    command=[sys.executable,'-I','-S','-B','-c',
        f'import sys; sys.path.insert(0,{str(implementation)!r}); from qperiapt_continuity_reference.session_cli import main; raise SystemExit(main())',
        '--provider-root',provider,'--directory',client_dir,'--client-id',client_id.hex(),
        '--key-file',root/'client-wrap.key']
    plan={'schema':'qperiapt-independent-publication/1','session_directory':str(session_dir),
          'peer_trust':str(root/'peer-trust.json'),'publication':str(root/'published/publication.json'),
          'credential':{'kind':'enrollment','path':str(root/'client-issued.json')},
          'policy_pins':inputs['policy_pins'],'policy_materials':inputs['policy_materials']}
    save(root/'client-publication.json',plan)

    def state():
        return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
                for directory in (client_dir,session_dir) for p in directory.rglob('*') if p.is_file()}

    def call(label,args,*,success=True):return run(command+args,'cli-'+label,success=success)
    def refused(label,args,expected=None):
        before=state();call(label,args,success=False)
        require(state()==before,'CLI refusal changed original state: '+label)
        if expected is not None:
            require((root/('cli-'+label+'.stderr')).read_text().strip()==expected,'CLI refused at the wrong boundary: '+label)

    bad_trust=json.loads((root/'peer-trust.json').read_bytes());bad_trust['directory']=list(os.urandom(32))
    save(root/'wrong-cli-trust.json',bad_trust)
    bad=copy.deepcopy(plan);bad['peer_trust']=str(root/'wrong-cli-trust.json');save(root/'wrong-cli-plan.json',bad)
    refused('wrong-directory',['prepare','--inputs',root/'wrong-cli-plan.json'])
    bad=copy.deepcopy(plan);bad['credential']['path']=str(root/'native-issued.json');save(root/'other-credential-plan.json',bad)
    refused('other-credential',['prepare','--inputs',root/'other-credential-plan.json'])
    expected={'prepared':True,'journal':b64(original)}
    require(call('prepare',['prepare','--inputs',root/'client-publication.json'])==expected,'CLI preparation identity')
    prepared=state()
    require(call('prepare-retry',['prepare','--inputs',root/'client-publication.json'])==expected and state()==prepared,'CLI preparation retry changed state')
    service=None;relay=None;thread=None;result={};frames=[]
    try:
        service=NativeService(root,'cli-native-service',native,inputs)
        def forward(frame,invocation):
            label='cli-wire-'+str(len(frames)+1);save(root/(label+'.request'),frame)
            response=TcpTransport(service.address)(frame,invocation.deadline,invocation.cancellation)
            save(root/(label+'.response'),response)
            frames.append({'label':label,'kind':frame[8],'request_sha256':hashlib.sha256(frame).hexdigest(),
                           'response_sha256':hashlib.sha256(response).hexdigest()})
            return response
        relay=Server(('127.0.0.1',0),forward)
        def serve():
            try:result['stats']=relay.serve()
            except BaseException as error:result['error']=error
        thread=threading.Thread(target=serve);thread.start()
        address=['--address',relay.address[0],str(relay.address[1])]
        connected=call('connect',['connect',*address]);sid=connected['session'];session_args=['--session='+sid]
        require(connected=={'session':sid,'peer_confirmation':'Recorded'} and len(frames)==2,'CLI bootstrap flights')
        require(call('connect-reopen',['connect',*address])==connected and len(frames)==2,'CLI reopen inferred a new bootstrap')
        wrong=b64(bytes([251])*32);require(wrong.startswith('-') and wrong!=sid,'negative-prefix regression identity')
        refused('wrong-session',['next','--session='+wrong],expected='ValueError: original session identity differs')
        refused('noncanonical-session',['next','--session='+sid+'='])
        refused('local-profile-witness',['next',*session_args,'--witness-address','127.0.0.1','1'])
        save(root/'cli-ad.bin',b'CLI application');save(root/'cli-body.bin',b'original CLI delivery')
        save(root/'cli-too-large.bin',b'x'*16385)
        message=call('next',['next',*session_args])['message'];message_args=[*session_args,'--message='+message]
        refused('oversized',['deliver',*message_args,'--plaintext',root/'cli-too-large.bin',
                            '--associated-data',root/'cli-ad.bin',*address])
        refused('rekey-bound',['rekey',*session_args,'--target','1','--exchanges','129',*address])
        require(call('deliver',['deliver',*message_args,'--plaintext',root/'cli-body.bin',
                '--associated-data',root/'cli-ad.bin',*address])=={'session':sid,'message':message,'consumption':'Confirmed'},'CLI first delivery')
        require(call('status',['message-status',*message_args])=={'session':sid,'message':message,'status':'Acknowledged'},'CLI committed ACK status')
        run([native,'read-inbox',root/'inbox.redb',b64(journal),sid,message,root/'cli-first-received.bin'],'cli-read-first')
        require((root/'cli-first-received.bin').read_bytes()==b'original CLI delivery','CLI first durable effect')
        lost=call('lost-next',['next',*session_args])['message'];lost_args=[*session_args,'--message='+lost]
        drop=DropResponse(service.address)
        call('lost',['deliver',*lost_args,'--plaintext',root/'cli-body.bin','--associated-data',root/'cli-ad.bin',
                     '--address',drop.address[0],str(drop.address[1])],success=False)
        lost_wire=drop.finish();save(root/'cli-lost.request',lost_wire['request']);save(root/'cli-lost-upstream.response',lost_wire['response'])
        require(call('lost-status',['message-status',*lost_args])=={'session':sid,'message':lost,'status':'Committed'},'CLI lost response inferred success')
        require(call('resume',['resume',*lost_args,'--associated-data',root/'cli-ad.bin',*address])==
                {'session':sid,'message':lost,'consumption':'Confirmed'},'CLI original resume')
        require(frames[-1]['request_sha256']==hashlib.sha256(lost_wire['request']).hexdigest() and
                frames[-1]['response_sha256']==hashlib.sha256(lost_wire['response']).hexdigest(),'CLI exact network retry differs')
        changed=call('rekey',['rekey',*session_args,'--target','1',*address])
        require(changed=={'session':sid,'epoch':1,'exchanges':2},'CLI rekey target/flight count')
        message=call('empty-next',['next',*session_args])['message'];save(root/'cli-empty.bin',b'')
        require(call('empty',['deliver',*session_args,'--message='+message,'--plaintext',root/'cli-empty.bin',
                             '--associated-data',root/'cli-empty.bin',*address])==
                {'session':sid,'message':message,'consumption':'Confirmed'},'CLI empty payload/AD after rekey')
        run([native,'read-inbox',root/'inbox.redb',b64(journal),sid,message,root/'cli-empty-received.bin'],'cli-read-empty')
        require((root/'cli-empty-received.bin').read_bytes()==b'','CLI empty effect readback')
        relay.close();thread.join(timeout=5);require(not thread.is_alive(),'CLI relay did not stop')
        if 'error' in result:raise result['error']
        stopped=service.stop()
        require(stopped['stats']['completed_responses']==8 and stopped['stats']['operation_errors']==0,'CLI native completion accounting')
        require(result['stats']['completed_responses']==7 and result['stats']['operation_errors']==0,'CLI relay completion accounting')
        from independent_inbound_cli import exercise as inbound
        received=inbound(command,call,root,outgoing,inputs,sid,original,run)
        return {'schema_version':1,'kind':'qperiapt.independent_session_cli','completed':True,
                'frames':frames,'native_service':stopped,'relay':result['stats'],'confirmed_epoch':2,'inbound':received,
                'scope':'Separate installed Python CLI processes and actual native TCP under explicit test authority. Both directions, durable inbox readback, lost ACK, receiver SIGKILL/restart, exact retry and two rekeys. No cross-host, simultaneous directions, witness-positive or real account authorization claim.'}
    finally:
        failures=[]
        if relay is not None:
            try:
                relay.close()
                if thread is not None:thread.join(timeout=5);require(not thread.is_alive(),'CLI relay remains alive')
            except BaseException as error:failures.append(error)
        if service is not None and service.result is None:
            try:service.stop()
            except BaseException as error:failures.append(error)
        if failures:raise BaseExceptionGroup('CLI workload cleanup failed',failures)
