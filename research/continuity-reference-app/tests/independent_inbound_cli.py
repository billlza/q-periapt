"""Installed inbound CLI: actual native traffic, receiver kill and original retry."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from native_exchange_fixture import save,b64
from native_network_driver import DropResponse
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.network_server import Server
from qperiapt_continuity_reference.wire import require


class Receiver:
    def __init__(self,root,label,command,session,inbox,*,witness_address=None):
        self.root,self.label=root,label;self.result=None
        self.stdout=root/(label+'.stdout');self.stderr=root/(label+'.stderr')
        with self.stdout.open('wb') as out,self.stderr.open('wb') as err:
            extra=[] if witness_address is None else ['--witness-address',*witness_address]
            self.process=subprocess.Popen([str(v) for v in command+['serve','--session='+session,
                '--inbox-directory',inbox,'--listen','127.0.0.1','0',*extra]],stdout=out,stderr=err)
        try:
            deadline=time.monotonic()+20
            while True:
                require(self.process.poll() is None,'independent receiver exited before readiness')
                raw=self.stdout.read_bytes();require(len(raw)<=4096,'independent readiness bound')
                if b'\n' in raw:break
                require(time.monotonic()<deadline,'independent readiness deadline');time.sleep(.01)
            ready=json.loads(raw.splitlines()[0])
            require(ready['service']=='Listening' and ready['carrier']=='QPCXCH01/TCP' and ready['session']==session,
                    'independent readiness identity')
            host,port=ready['address'];require(host=='127.0.0.1' and type(port) is int and 0<port<=65535,'independent listen endpoint')
            self.address=host,port
        except BaseException:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
            raise

    def stop(self,*,kill=False):
        require(self.result is None and self.process.poll() is None,'receiver already terminal')
        self.process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
        try:status=self.process.wait(timeout=35)
        finally:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
        require(status==(-9 if kill else 0) and not self.stderr.read_bytes(),'receiver stop disposition')
        lines=self.stdout.read_bytes().splitlines();require(len(lines)==(1 if kill else 2),'receiver output inventory')
        self.result={'label':self.label,'pid':self.process.pid,'exit':status}
        if not kill:
            stopped=json.loads(lines[1]);require(stopped['service']=='Stopped','receiver stop receipt')
            self.result['stats']=stopped['stats']
        return self.result


def exercise(command,call,root,outgoing,inputs,session,journal,run):
    inbox=root/'independent-inbox';inbox.mkdir(mode=0o700)
    selected=['--session='+session,'--inbox-directory',inbox]
    receivers=[];relay=None;thread=None;drop=None;observed={};frames=[]
    def action(label,value,*,success=True):
        path=root/(label+'.json');save(path,dict(inputs,schema='qperiapt-native-outgoing/1',action=value))
        return run([outgoing,path,session],label,success=success)
    def deliver(message,body,address):
        return {'operation':'deliver_tcp','message':list(message),'plaintext':list(body),'associated_data':[],
                'address':f'{address[0]}:{address[1]}'}
    def read(label,message,output,body):
        value=call(label,['read-inbox',*selected,'--message='+b64(message),'--output',output])
        require(value=={'session':session,'message':b64(message),'delivery':'Exported','bytes':len(body)}
                and output.read_bytes()==body,'independent inbox readback differs')
    try:
        call('inbox-missing',['recover-inbox',*selected],success=False)
        require(not list(inbox.iterdir()),'missing independent inbox was initialized')
        require(call('inbox-provision',['provision-inbox',*selected])==
                {'session':session,'journal':b64(journal),'inbox':'Provisioned'},'inbox provision identity')
        before=(inbox/'head').read_bytes()
        call('inbox-duplicate',['provision-inbox',*selected],success=False)
        require((inbox/'head').read_bytes()==before,'duplicate inbox creation replaced history')
        require(call('inbox-recover',['recover-inbox',*selected])==
                {'session':session,'journal':b64(journal),'inbox':'Recovered'},'inbox original recovery')
        call('inbox-wrong-session',['recover-inbox','--session='+b64(os.urandom(32)),'--inbox-directory',inbox],success=False)
        first=Receiver(root,'cli-inbound-first',command,session,inbox);receivers.append(first)
        message=bytes(action('cli-native-next',{'operation':'next'})['message'])
        body=b'original native inbound CLI'
        require(action('cli-native-deliver',deliver(message,body,first.address))=={'consumption':'Confirmed'},'native inbound delivery')
        read('inbox-read',message,root/'cli-inbound-first.bin',body)
        lost=bytes(action('cli-native-lost-next',{'operation':'next'})['message'])
        drop=DropResponse(first.address)
        action('cli-native-lost',deliver(lost,b'original lost inbound CLI',drop.address),success=False)
        lost_wire=drop.finish();drop=None
        save(root/'cli-inbound-lost.request',lost_wire['request'])
        save(root/'cli-inbound-lost.response',lost_wire['response'])
        # The actual ACK was generated, then lost. Kill this real receiver
        # before the sender can reconcile; retain its original private state.
        first.stop(kill=True)
        require(action('cli-native-lost-status',{'operation':'status','message':list(lost)})=={'status':'Committed'},'lost reply inferred confirmation')
        second=Receiver(root,'cli-inbound-reopened',command,session,inbox);receivers.append(second)
        def forward(frame,invocation):
            label='cli-inbound-wire-'+str(len(frames)+1);save(root/(label+'.request'),frame)
            reply=TcpTransport(second.address)(frame,invocation.deadline,invocation.cancellation)
            save(root/(label+'.response'),reply)
            frames.append({'label':label,'kind':frame[8],'request_sha256':hashlib.sha256(frame).hexdigest(),
                           'response_sha256':hashlib.sha256(reply).hexdigest()})
            return reply
        relay=Server(('127.0.0.1',0),forward)
        def serve():
            try:observed['stats']=relay.serve()
            except BaseException as error:observed['error']=error
        thread=threading.Thread(target=serve);thread.start()
        original_effect=(inbox/'head').read_bytes()
        require(action('cli-native-resume',deliver(lost,b'original lost inbound CLI',relay.address))=={'consumption':'Confirmed'},'original inbound retry')
        require((inbox/'head').read_bytes()==original_effect,'consumed retry repeated host effect')
        require((root/'cli-inbound-wire-1.request').read_bytes()==lost_wire['request']
                and (root/'cli-inbound-wire-1.response').read_bytes()==lost_wire['response'],'inbound retry changed exact bytes')
        require(action('cli-native-rekey',{'operation':'rekey_tcp','target':2,'exchanges':4,
                'address':f'{relay.address[0]}:{relay.address[1]}'})=={'epoch':2,'exchanges':2},'native inbound rekey')
        empty=bytes(action('cli-native-empty-next',{'operation':'next'})['message'])
        require(action('cli-native-empty',deliver(empty,b'',relay.address))=={'consumption':'Confirmed'},'post-rekey empty delivery')
        relay.close();thread.join(timeout=5);require(not thread.is_alive(),'inbound relay not joined')
        if 'error' in observed:raise observed['error']
        second.stop()
        read('inbox-read-lost',lost,root/'cli-inbound-lost.bin',b'original lost inbound CLI')
        read('inbox-read-empty',empty,root/'cli-inbound-empty.bin',b'')
        call('inbox-export-exists',['read-inbox',*selected,'--message='+b64(message),
                                  '--output',root/'cli-inbound-first.bin'],success=False)
        require((root/'cli-inbound-first.bin').read_bytes()==body,'exclusive export replaced original output')
        require(second.result['stats']['completed_responses']==4 and second.result['stats']['operation_errors']==0
                and observed['stats']['completed_responses']==4 and observed['stats']['operation_errors']==0,'inbound completion accounting')
        return {'receivers':[r.result for r in receivers],'relay':observed['stats'],'frames':frames,
                'confirmed_epoch':2,'effects':3,'original_effect_unchanged_on_retry':True}
    finally:
        failures=[]
        if drop is not None:
            try:drop.finish()
            except BaseException as error:failures.append(error)
        if relay is not None:
            try:
                relay.close()
                if thread is not None:thread.join(timeout=5);require(not thread.is_alive(),'inbound relay remains alive')
            except BaseException as error:failures.append(error)
        for receiver in receivers:
            if receiver.result is None:
                try:receiver.stop()
                except BaseException as error:failures.append(error)
        if failures:raise BaseExceptionGroup('inbound CLI workload cleanup failed',failures)
