#!/usr/bin/env python3
"""Real HTTP account issuance composed with native/independent common-account owners.

Software Passkeys authenticate isolated test accounts. No fixture account-root
signer, clock override, reset or recreation is available to this controller.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys

parser=argparse.ArgumentParser(description=__doc__)
for name in ('account-host','account-client','sdk-authority','publisher','witness','native-device',
             'native-session','native-outgoing','implementation-root','provider-root','output'):
    parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--wait-for-credential-expiry',action='store_true',help='Wait for both original one-hour HTTP credentials to expire under a still-live signed test policy')
args=parser.parse_args();implementation=args.implementation_root.resolve(strict=True)
sys.path.insert(0,str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider,_backend=load_provider(args.provider_root)
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.wire import require
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_exchange_fixture import b64,save
from native_network_driver import NativeService,DropResponse
from independent_inbound_cli import Receiver
from witness_cli_exchange import WitnessHost
from host_replacement_process import Commands,AccountHost,AccountProbe,RecordingRelay,policy
from host_replacement_device import Native,Independent,authority,invite,approve,issued
from host_account_credential_grants import renew

root=args.output;require(root.is_absolute() and not root.exists(),'fresh absolute cohort output required');root.mkdir(mode=0o700)
run=Commands(root);paths={name:getattr(args,name).resolve(strict=True) for name in
    ('account_host','account_client','sdk_authority','publisher','witness','native_device','native_session','native_outgoing')}
binaries={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths.values()}
sources=[*Path(__file__).resolve().parent.glob('*.py'),*(implementation/'qperiapt_continuity_reference').glob('*.py')]
inventory=lambda:{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
before=inventory();host=probe=witness=receiver=recording=None;services=[];peers=[];sessions={};pending={};deliveries=[]
result={'schema_version':2 if args.wait_for_credential_expiry else 1,'kind':'qperiapt.authenticated_account_credential','completed':False,'release_claim_eligible':False,
    'source_files':before,'native_sha256':binaries,'provider':provider.__version__,'clock':'actual OS time',
    'implementation':str(implementation/'qperiapt_continuity_reference/credential_cli.py')}
try:
    witness=WitnessHost(root,paths['witness'],run)
    family,start,_selected,_selection=policy(root,paths['sdk_authority'],paths['publisher'],witness,run,
        valid_for=7200 if args.wait_for_credential_expiry else 1800)
    host=AccountHost(root,paths['account_host'],family,run);host.start('account-first')
    probe=AccountProbe(root,paths['account_client'],host.origin)
    for name in ('alice',):
        probe.register(name);probe.request(name,name+'-prepare-root','/api/enrollment/root/prepare',{})
    native=Native(root,paths['native_device'],paths['native_session'],probe,witness,run,start,defer_preparation=True)
    auth,_current=authority(probe,'alice','cohort-authority')
    for label in ('peer',):
        peer=Independent(root,label,invite(probe,'alice',label+'-invitation'),auth,implementation,args.provider_root,witness,run)
        approve(probe,'alice',peer.invitation,peer.proof,label+'-approve')
        peer.accept(issued(probe,'alice',peer.invitation,label+'-issue'),probe.request('alice',label+'-current','/api/enrollment/root'))
        peers.append(peer)
    current=peer.current;save(root/'cohort-original-current.json',current)
    require(current['account']==native.current['account'],'cohort endpoints do not share an account')
    native.current_path=root/'cohort-original-current.json';native.current=current
    native.local_inputs=[native.current_path,*native.local_inputs[1:]]
    run([native.binary,'refresh-roster',*native.common,*native.local_inputs],'native-refresh-before-session')
    native.prepare_and_publish(start)
    key_hashes={p.label:hashlib.sha256(p.key_file.read_bytes()).hexdigest() for p in peers}
    witness_keys=witness.keys();native_identity=native.status('cohort-native-before')
    save(root/'associated-data.bin',b'original native independent cohort')
    for peer in peers:
        peer.prepare(native)
        witness.enroll(peer.label,peer.prepared,peer.current,bytes(peer.invitation['device']),peer.journal,encoded(peer.issued['certificate'],65536))
        service=NativeService(root,peer.label+'-before-service',paths['native_session'],native.inputs(peer));services.append(service)
        sid=peer.connect(service.address,'connect');sessions[peer.label]=sid
        message=peer.next(sid,'lost-next');pending[peer.label]=message
        relay=DropResponse(service.address);body=(peer.label+' original lost ACK').encode()
        peer.deliver(sid,message,body,relay.address,'lost-send',success=False)
        observed=relay.finish();save(root/(peer.label+'-lost.request'),observed['request']);save(root/(peer.label+'-lost.response'),observed['response'])
        require(peer.cli('lost-status',['message-status','--session='+sid,'--message='+message])['status']=='Committed','cohort lost ACK inferred success')
        native.read(sid,message,body,peer.label+'-original-effect');service.stop()
    require(peers[0].journal!=native.journal and peers[0].invitation['device']!=native.invitation['device'],
            'common-account device owners were not distinct')
    if args.wait_for_credential_expiry:
        from host_account_expiry import observe
        result['expiry']=observe(root,native,peers[0],host,probe,witness,run,sessions['peer'])
    result['renewal']=renew(root,native,peers[0],probe,host,witness,run,sessions)
    witness.service.stop(kill=True);witness.start('witness-reopened')
    for peer in peers:
        label=peer.label;sid=sessions[label];message=pending[label]
        service=NativeService(root,label+'-after-service',paths['native_session'],native.inputs(peer));services.append(service)
        recording=RecordingRelay(root,service.address)
        peer.deliver(sid,message,None,recording.address,'resume',resume=True)
        recording.close()
        require(len(recording.rows)==1 and recording.rows[0]['outcome']=='response'
                and (root/'replacement-wire-1.request').read_bytes()==(root/(label+'-lost.request')).read_bytes()
                and (root/'replacement-wire-1.response').read_bytes()==(root/(label+'-lost.response')).read_bytes(),
                'cohort recovery changed original ciphertext or acknowledgement')
        result['recovery_wire']=recording.rows;result['recovery_relay']=recording.result['stats']
        native.read(sid,message,(label+' original lost ACK').encode(),label+'-recovered-effect')
        require((root/(label+'-original-effect.bin')).read_bytes()==(root/(label+'-recovered-effect.bin')).read_bytes(),
                'cohort recovery changed original remote effect')
        require(peer.cli('rekey',['rekey','--session='+sid,'--target','1','--address',*service.address])==
                {'session':sid,'epoch':1,'exchanges':2},'cohort original rekey')
        fresh=peer.next(sid,'fresh-next');peer.deliver(sid,fresh,(label+' after cohort renewal').encode(),service.address,'fresh-send')
        native.read(sid,fresh,(label+' after cohort renewal').encode(),label+'-fresh-effect')
        inbox=root/(label+'-inbox');inbox.mkdir(mode=0o700)
        peer.cli('inbox',['provision-inbox','--session='+sid,'--inbox-directory',inbox])
        receiver=Receiver(root,label+'-receiver',peer.command,sid,inbox,witness_address=witness.address)
        def outgoing(action,suffix):
            path=root/(label+'-'+suffix+'.json');save(path,dict(native.inputs(peer),schema='qperiapt-native-outgoing/1',action=action))
            return run([paths['native_outgoing'],path,sid],label+'-'+suffix)
        address=f'{receiver.address[0]}:{receiver.address[1]}'
        require(outgoing({'operation':'rekey_tcp','target':2,'exchanges':8,'address':address},'native-rekey')=={'epoch':2,'exchanges':2},
                'cohort reverse rekey')
        reverse=outgoing({'operation':'next'},'native-next')['message'];body=(label+' reverse cohort effect').encode()
        require(outgoing({'operation':'deliver_tcp','message':reverse,'plaintext':list(body),'associated_data':[],'address':address},'native-send')==
                {'consumption':'Confirmed'},'cohort reverse consumption')
        receiver.stop();deliveries.append(receiver.result);receiver=None
        peer.cli('read-reverse',['read-inbox','--session='+sid,'--message='+b64(bytes(reverse)),'--inbox-directory',inbox,'--output',root/(label+'-reverse.bin')])
        require((root/(label+'-reverse.bin')).read_bytes()==body,'cohort reverse durable effect')
        service.stop()
    require(native.status('cohort-native-after')==native_identity and witness.keys()==witness_keys
            and all(hashlib.sha256(p.key_file.read_bytes()).hexdigest()==key_hashes[p.label] for p in peers),'cohort original identities changed')
    witness.close();host.close();probe.finish()
    require(inventory()==before and {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths.values()}==binaries,'cohort source or executable changed')
    result.update(completed=True,sessions=sessions,original_pending_messages=pending,original_keys_unchanged=True,witness_keys_unchanged=True,
        original_wire_unchanged=True,
        effects=3,confirmed_epoch=2,services=[s.result for s in services],receivers=deliveries,
        witness_services=[s.result for s in witness.services],account_services=host.services,
        scope='Real reference HTTP account service and software Passkey authentication; native and independent original owners share one account. Sequential extensions form one final roster, exact lost grant output survives account restart; both owners adopt complete signed sets through original CLIs and native witness approval, recover the original unknown ACK, rekey and exchange bidirectional effects. No fixture account signer, human Passkey, mobile or PCS claim.')
    result['scope'] += (' Both original credentials naturally expired under a still-live signed policy; expired operations were refused and original software Passkey login restored account access before G.'
        if args.wait_for_credential_expiry else ' This profile does not wait for credential expiry.')
except BaseException as error:result['failure']=str(error);raise
finally:
    errors=[]
    closers=([recording.close] if recording is not None and not recording.closed else [])
    closers+=([receiver.stop] if receiver is not None and receiver.result is None else [])+[s.stop for s in services if s.result is None]
    closers+=([probe.close] if probe else [])+([host.close] if host else [])+([witness.close] if witness else [])
    for close in closers:
        try:close()
        except BaseException as error:errors.append(str(error))
    result.update(commands=run.rows,account_requests=[] if probe is None else probe.rows,cleanup_errors=errors)
    if errors:result['completed']=False
    save(root/'RESULT.json',result)
    if errors:raise RuntimeError('cohort cleanup failed: '+'; '.join(errors))
print(json.dumps(result))
