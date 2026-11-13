"""Actual-time standalone witness and independent/native session commands.

Explicit isolated test account approval; no production identity or clock override.
The witness persists its own signing key, identity and monotonic head on disk.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
import sys
from native_exchange_fixture import save,b64
from native_network_driver import NativeService,DropResponse
from independent_inbound_cli import Receiver
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.wire import VerificationKey,require
from qperiapt_continuity_reference.witness import Pin


class WitnessHost:
    def __init__(self,root,binary,run):
        self.root,self.binary,self.run=root,binary,run
        self.identity=os.urandom(32);save(root/'witness-identity.bin',self.identity)
        self.database=root/'witness-host.redb';self.services=[];self.service=None;self.address=None
        pin=run(self.command('init'),'witness-init')
        self.public=pin;self.pin=Pin(bytes(pin['identity']),VerificationKey(encoded(pin['key'],1985,1985)))
        require(self.pin.identity==self.identity,'original witness identity differs')

    def command(self,action,*args):return [self.binary,action,self.database,b64(self.identity),*args]

    def start(self,label):
        address='127.0.0.1:0' if self.address is None else self.endpoint()
        self.service=NativeService(self.root,label,self.binary,
            arguments=self.command('serve',address)[1:],carrier='ContinuityAnchor/TCP')
        self.services.append(self.service)
        if self.address is not None:require(self.service.address==self.address,'original witness endpoint changed')
        self.address=self.service.address

    def endpoint(self):return f'{self.address[0]}:{self.address[1]}'

    def enroll(self,label,request,current,device,journal,certificate,*,success=True,head=None):
        # This driver is the explicit isolated test operator. Neither network
        # endpoint constructs this separately retained authority approval.
        trust={'schema':'qperiapt-witness-enrollment-trust/1','account':current,'device':list(device),
            'generation':1,'journal':list(journal),'genesis_head':request['head'] if head is None else head,
            'certificate':b64(certificate),'policy':{
                'pins':json.loads((self.root/'policy-pins.json').read_bytes()),
                'materials':json.loads((self.root/'policy-materials.json').read_bytes())}}
        save(self.root/(label+'-witness-trust.json'),trust);save(self.root/(label+'-genesis.json'),request)
        return self.run(self.command('enroll',self.root/(label+'-witness-trust.json'),self.root/(label+'-genesis.json')),
            label+'-witness-enroll',success=success)

    def keys(self):
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.iterdir()
                if p.name.startswith('witness-') and p.suffix in ('.wrap','.signer')}

    def close(self):
        for service in self.services:
            if service.result is None:service.stop()


def exercise(implementation,provider,client_dir,session_dir,client_id,root,native,outgoing,inputs,
             journal,original,run,witness,current,device,certificate,*,account_issuer=None):
    command=[sys.executable,'-I','-S','-B','-c',
        f'import sys; sys.path.insert(0,{str(implementation)!r}); from qperiapt_continuity_reference.session_cli import main; raise SystemExit(main())',
        '--provider-root',provider,'--directory',client_dir,'--client-id',client_id.hex(),'--key-file',root/'client-wrap.key']
    plan={'schema':'qperiapt-independent-publication/1','session_directory':str(session_dir),
        'peer_trust':str(root/'peer-trust.json'),'publication':str(root/'published/publication.json'),
        'credential':{'kind':'enrollment','path':str(root/'client-issued.json')},
        'policy_pins':inputs['policy_pins'],'policy_materials':inputs['policy_materials']}
    save(root/'witness-publication.json',plan)
    def call(label,args,*,success=True,selected=True):
        extra=['--witness-address',*witness.address] if selected and args[0] not in ('prepare','provision-inbox','recover-inbox','read-inbox') else []
        result=run(command+args+extra,'witness-cli-'+label,success=success)
        if not success:require(not (root/('witness-cli-'+label+'.stdout')).read_bytes(),'refusal emitted a result')
        return result
    def files():
        return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
                for directory in (client_dir,session_dir) for p in directory.rglob('*') if p.is_file()}
    prepared=call('prepare',['prepare','--inputs',root/'witness-publication.json'])
    require(set(prepared)=={'preparation','subject','head'} and prepared['preparation']=='RequiresWitnessEnrollment'
            and len(prepared['subject'])==96 and bytes(prepared['subject'][:32])==original and len(prepared['head'])==32,
            'required witness preparation did not export original genesis')
    before=files()
    require(call('prepare-retry',['prepare','--inputs',root/'witness-publication.json'])==prepared
            and before==files(),'original witness preparation changed')
    service=NativeService(root,'witness-native-service',native,inputs);receiver=None
    try:
        address=['--address',*service.address]
        call('unenrolled',['connect',*address],success=False)
        require(files()==before,'unenrolled witness released or changed client state')
        witness.enroll('wrong-head',prepared,current,device,original,certificate,success=False,head=list(os.urandom(32)))
        witness.enroll('independent',prepared,current,device,original,certificate)
        call('missing-carrier',['connect',*address],success=False,selected=False)
        require(files()==before,'missing witness changed original state')
        connected=call('connect',['connect',*address]);sid=connected['session']
        require(connected=={'session':sid,'peer_confirmation':'Recorded'},'required witness bootstrap confirmation')
        selected=['--session='+sid]
        require(call('connect-reopen',['connect',*address])==connected,'reopen replaced original session')
        body=b'required witness original delivery';save(root/'witness-body.bin',body);save(root/'witness-ad.bin',b'')
        message=call('next',['next',*selected])['message']
        require(call('deliver',['deliver',*selected,'--message='+message,'--plaintext',root/'witness-body.bin',
            '--associated-data',root/'witness-ad.bin',*address])['consumption']=='Confirmed','witness delivery')
        run([native,'read-inbox',root/'inbox.redb',b64(journal),sid,message,root/'witness-first.bin'],'witness-read-first')
        require((root/'witness-first.bin').read_bytes()==body,'native durable first effect')
        lost=call('lost-next',['next',*selected])['message']
        relay=DropResponse(service.address)
        call('lost',['deliver',*selected,'--message='+lost,'--plaintext',root/'witness-body.bin',
            '--associated-data',root/'witness-ad.bin','--address',*relay.address],success=False)
        observed=relay.finish();save(root/'witness-lost.request',observed['request']);save(root/'witness-lost.response',observed['response'])
        require(call('lost-status',['message-status',*selected,'--message='+lost])['status']=='Committed','lost ACK inferred success')
        keys=witness.keys();require(len(keys)==2,'original witness protected key inventory')
        save(root/'witness-key-hashes-before.json',keys)
        witness.service.stop(kill=True)
        call('offline',['next',*selected],success=False)
        require(witness.run(witness.command('pin'),'witness-original-pin')==witness.public,'original pin changed')
        witness.start('witness-reopened')
        require(witness.keys()==keys,'witness restart regenerated keys')
        witness.enroll('advanced-retry',prepared,current,device,original,certificate)
        account_renewal=None
        if account_issuer is not None:
            from witness_account_credential_cli import exercise as account_credential
            account_renewal=account_credential(account_issuer,implementation,provider,root,client_dir,
                session_dir,client_id,original,journal,sid,lost,witness,prepared)
        require(call('resume',['resume',*selected,'--message='+lost,'--associated-data',root/'witness-ad.bin',*address])['consumption']=='Confirmed',
            'original pending message did not resume after witness restart')
        run([native,'read-inbox',root/'inbox.redb',b64(journal),sid,lost,root/'witness-lost.bin'],'witness-read-lost')
        require((root/'witness-lost.bin').read_bytes()==body,'lost original durable effect')
        require(call('rekey',['rekey',*selected,'--target','1',*address])=={'session':sid,'epoch':1,'exchanges':2},'witness rekey1')
        inbox=root/'witness-inbox';inbox.mkdir(mode=0o700)
        call('provision-inbox',['provision-inbox',*selected,'--inbox-directory',inbox])
        receiver=Receiver(root,'witness-independent-service',command,sid,inbox,witness_address=witness.address)
        def action(label,value):
            path=root/(label+'.json');save(path,dict(inputs,schema='qperiapt-native-outgoing/1',action=value))
            return run([outgoing,path,sid],label)
        require(action('witness-native-rekey',{'operation':'rekey_tcp','target':2,'exchanges':8,
            'address':f'{receiver.address[0]}:{receiver.address[1]}'})=={'epoch':2,'exchanges':2},'witness native rekey2')
        incoming=bytes(action('witness-native-next',{'operation':'next'})['message'])
        require(int.from_bytes(incoming[:8],'big')==2,'native post-rekey epoch')
        reverse=b'native required witness epoch two'
        require(action('witness-native-delivery',{'operation':'deliver_tcp','message':list(incoming),'plaintext':list(reverse),
            'associated_data':[],'address':f'{receiver.address[0]}:{receiver.address[1]}'})=={'consumption':'Confirmed'},'native required witness delivery')
        receiver.stop()
        call('read-inbox',['read-inbox',*selected,'--inbox-directory',inbox,'--message='+b64(incoming),'--output',root/'witness-reverse.bin'])
        require((root/'witness-reverse.bin').read_bytes()==reverse,'independent durable reverse effect')
        service.stop();witness.close()
        require(witness.keys()==keys,'witness protected keys changed')
        save(root/'witness-key-hashes-after.json',witness.keys())
        return {'schema_version':2 if account_issuer is not None else 1,'kind':'qperiapt.required_witness_session_cli','completed':True,
            'account_credential':account_renewal,
            'session':sid,'confirmed_epoch':2,'genesis':prepared,'witness_keys_unchanged':True,
            'native_service':service.result,'independent_service':receiver.result,
            'witness_services':[s.result for s in witness.services],
            'effects':3,'original_lost_message':lost,
            'scope':'Explicit test authority; actual OS clock and separate native witness/session and independent CLI processes over local TCP. Required first use, missing/unenrolled/offline refusal, loss of actual ACK, witness SIGKILL/reopen with original keys, exact original enrollment retry after advance, same session resume, two rekeys and bidirectional durable effects. Optional complete-account G section records separate native operator approval and output-loss recovery. No cross-host, elapsed expiry, physical power-loss or continuous PQ security-recovery claim.'}
    finally:
        if receiver is not None and receiver.result is None:receiver.stop()
        if service.result is None:service.stop()
