#!/usr/bin/env python3
"""Actual-time native CLI to independent owned session, with explicit test authority.

The application APIs contain no fixture issuer or clock override. This workload
supplies test approval; it is not real user authorization or deployed networking.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
for name in ('native-device','native-session','native-outgoing','crash-probe','implementation-root','provider-root','output'):
    parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--network',action='store_true',help='Fresh bidirectional TCP workload instead of the file/crash workload')
args = parser.parse_args()
implementation = args.implementation_root.resolve(strict=True)
sys.path.insert(0,str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider, backend = load_provider(args.provider_root)
from cryptography.exceptions import InvalidSignature
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.identity import DevicePin
from qperiapt_continuity_reference.authority import Pins
from qperiapt_continuity_reference.publication import Publication
from qperiapt_continuity_reference.wire import require
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_exchange_fixture import Issuer,b64,save,wire
from native_exchange_cuts import exercise as crash_cuts
from native_connection_checks import exercise as connection_checks
from native_connection_flow import exercise as connection_flow
from native_inbound_flow import exercise as inbound_flow
from qperiapt_continuity_reference.connection import Consumption
from qperiapt_continuity_reference.connection_run import Run

root = args.output.resolve(); root.mkdir(mode=0o700)
issuer = Issuer(root)
commands, refusals = [], []
device = args.native_device.resolve(strict=True)
session_cli = args.native_session.resolve(strict=True)
crash_probe = args.crash_probe.resolve(strict=True)
outgoing = args.native_outgoing.resolve(strict=True)
native_hashes = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (device,session_cli,crash_probe,outgoing)}


def run(argv, label, *, success=True, json_output=True, deadline=None):
    remaining=60 if deadline is None else min(60,deadline-time.monotonic())
    require(remaining>0,'native carrier invocation expired')
    result = subprocess.run([str(x) for x in argv],capture_output=True,timeout=remaining)
    save(root/(label+'.stdout'),result.stdout); save(root/(label+'.stderr'),result.stderr)
    commands.append({'label':label,'exit':result.returncode})
    require((result.returncode == 0) == success,'native result differs: '+label+': '+result.stderr.decode())
    if success:
        require(not result.stderr,'unexpected native diagnostics: '+label)
        return json.loads(result.stdout) if json_output else result.stdout
    refusals.append(label)


def refuse(label, action):
    try: action()
    except (ValueError,InvalidSignature): refusals.append(label)
    else: raise ValueError('missing refusal: '+label)


def frame(kind, body): return b'QPCXCH01'+bytes([kind])+body
def payload(wire, kind):
    require(10 <= len(wire) <= 65536 and wire[:9] == frame(kind,b''),'exchange response frame')
    return wire[9:]
def pair(first, second): return len(first).to_bytes(2,'big')+first+second
def split(body):
    require(len(body)>=2,'exchange pair header'); size=int.from_bytes(body[:2],'big')
    require(size<=len(body)-2,'exchange pair bound'); return body[2:2+size],body[2+size:]


native_dir = root/'native'; native_dir.mkdir(mode=0o700)
native_invitation, native_offer = issuer.invitation('native')
common = [native_dir,root/'native-wrap.key',root/'native-invitation.json']
key_result=run([device,'provision-key',root/'native-wrap.key'],'native-key',json_output=False)
require(key_result==b'Host wrapping key provisioned; retain this exact file separately from journal backups.\n',
        'unexpected key provision output')
run([device,'begin',*common],'native-begin')
run([device,'request',*common,root/'native-request.bin'],'native-request')
native_certificate = issuer.certificate(native_offer,(root/'native-request.bin').read_bytes())

client_dir, session_dir = root/'client',root/'session'
client_dir.mkdir(mode=0o700); session_dir.mkdir(mode=0o700)
client_id, key = os.urandom(32),os.urandom(32)
save(root/'client-key-and-id',key+client_id)
client_invitation, client_offer = issuer.invitation('client')
client = EnrollmentClient.begin(client_dir,client_id,key,wire(issuer.authority_json),wire(client_invitation),int(time.time()))
try:
    certificate = issuer.certificate(client_offer,client.request(int(time.time())))
    current = issuer.current()
    save(root/'native-issued.json',issuer.issued(native_invitation,native_certificate))
    accepted = run([device,'accept',*common,root/'native-issued.json',root/'current.json',
                    root/'policy-pins.json',root/'policy-materials.json'],'native-accept')
    original_journal = client.accept(wire(client_invitation),wire(issuer.issued(client_invitation,certificate)),
        wire(current),(root/'policy-pins.json').read_bytes(),(root/'policy-materials.json').read_bytes(),int(time.time()))
    run([device,'prepare',*common,root/'current.json',root/'policy-pins.json',root/'policy-materials.json'],'native-prepare')
    active_args = [*common,root/'current.json',root/'policy-pins.json',root/'policy-materials.json','none']
    identifier = run([device,'publication-next',*active_args],'native-publication-id')['publication']
    directory = os.urandom(32)
    save(root/'plan.json',{'schema':'qperiapt-native-publication-plan/1','directory':list(directory),
                         'valid_from':issuer.start,'valid_until':issuer.start+600})
    published = root/'published'; published.mkdir(mode=0o700)
    run([device,'publish',*active_args,b64(bytes(identifier)),root/'plan.json',published],'native-publish')
    raw = (published/'publication.json').read_bytes(); publication = Publication.decode(raw)
    checkpoint = bytes(issuer.checkpoint['digest'])
    def pin(offer): return DevicePin(issuer.root.public(),issuer.account,1,checkpoint,offer.intent.device,1)
    p = issuer.policy.pins
    pins = Pins(p.sdk_root,p.sdk_state,p.policy_root,p.policy_version,p.policy_digest,
                pin(client_offer),pin(native_offer),directory)
    context = publication.verify(pins,issuer.policy.materials,certificate,issuer.roster,int(time.time()))
    refuse('wrong-directory',lambda:publication.verify(replace(pins,directory=os.urandom(32)),issuer.policy.materials,
                                                       certificate,issuer.roster,int(time.time())))
    refuse('wrong-responder',lambda:publication.verify(replace(pins,responder=pin(client_offer)),issuer.policy.materials,
                                                       certificate,issuer.roster,int(time.time())))
    changed = publication.manifest[:-1]+bytes([publication.manifest[-1]^1])
    refuse('manifest-signature',lambda:replace(publication,manifest=changed).verify(pins,issuer.policy.materials,
                                                          certificate,issuer.roster,int(time.time())))
    changed = publication.pq_proof[:-1]+bytes([publication.pq_proof[-1]^1])
    refuse('membership-proof',lambda:replace(publication,pq_proof=changed).verify(pins,issuer.policy.materials,
                                                          certificate,issuer.roster,int(time.time())))
    bad = json.loads(raw); bad['root']=b64(issuer.root.public().raw)
    refuse('publication-cannot-select-root',lambda:Publication.decode(wire(bad)))
    bad = json.loads(raw); bad['journal'][0] ^= 1
    refuse('journal-correlation',lambda:Publication.decode(wire(bad)))
    refuse('duplicate-json',lambda:Publication.decode(raw[:-1]+b',"schema":"qperiapt-native-publication/1"}'))
    save(root/'bundle.bin',publication.bundle(certificate,issuer.roster).wire)
    trust={'schema':'qperiapt-native-peer-trust/1','directory':list(directory),
           'initiator':{'current':current,'device':list(client_offer.intent.device),'generation':1},
           'responder':{'current':current,'device':list(native_offer.intent.device),'generation':1}}
    save(root/'peer-trust.json',trust)
    run([session_cli,'provision-inbox',root/'inbox.redb',b64(bytes(accepted['journal']))],'native-inbox')
    with (root/'inbox.redb').open('rb') as file: inbox_header=file.read(10)
    require(len(inbox_header)==10 and inbox_header[9]&4!=0,'new inbox omitted two-phase commit')
    run([session_cli,'read-inbox',root/'inbox.redb',b64(os.urandom(32)),b64(os.urandom(32)),
         b64(os.urandom(32)),root/'wrong-inbox-output.bin'],'wrong-inbox-journal',success=False)
    require(not (root/'wrong-inbox-output.bin').exists(),'wrong inbox journal released data')
    client.prepare(session_dir,publication.inputs(pins,issuer.policy.materials,certificate,issuer.roster),int(time.time()))

    native_inputs={'device_directory':str(native_dir),'wrapping_key':str(root/'native-wrap.key'),
        'invitation':str(root/'native-invitation.json'),'current_root':str(root/'current.json'),
        'policy_pins':str(root/'policy-pins.json'),'policy_materials':str(root/'policy-materials.json'),
        'witness_endpoint':'none','peer_trust':str(root/'peer-trust.json'),'bundle':str(root/'bundle.bin')}

    def make_invocation(label, operation, request, *, inbox=None, trust_path=None):
        target=root/(label+'-output'); target.mkdir(mode=0o700)
        save(root/(label+'.request'),request)
        invocation={**native_inputs,'schema':'qperiapt-native-exchange/1',
            'peer_trust':str(trust_path or root/'peer-trust.json'),
            'operation':operation,'request':str(root/(label+'.request')),'inbox':str(inbox or root/'inbox.redb'),
            'output_directory':str(target)}
        save(root/(label+'.json'),invocation)
        return root/(label+'.json')

    def exchange(label, operation, request, *, inbox=None, trust_path=None, success=True, deadline=None):
        invocation=make_invocation(label,operation,request,inbox=inbox,trust_path=trust_path)
        target=root/(label+'-output')
        run([session_cli,'exchange',invocation],label,success=success,deadline=deadline)
        if success: return (target/'response.bin').read_bytes()
        require(not (target/'response.bin').exists(),'rejected request released output')

    if args.network:
        from native_network_flow import exercise as network_flow
        client,report=network_flow(client,client_dir,client_id,key,root,session_cli,outgoing,native_inputs,
                                   bytes(accepted['journal']),run,refusals)
        require({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (device,session_cli,crash_probe,outgoing)}==native_hashes,'native executable changed')
        report.update(native_sha256=native_hashes,commands=commands,refusals=refusals,
                      provider=provider.__version__,implementation=str(implementation/'qperiapt_continuity_reference/network.py'),
                      clock='actual OS time')
        save(root/'RESULT.json',report);print(json.dumps(report))
        raise SystemExit(0)

    with client.session(int(time.time())) as child:
        initial = child.initial(now=int(time.time()))
        exchange('missing-inbox',{'operation':'bootstrap'},frame(1,initial),inbox=root/'missing.redb',success=False)
        require(not (root/'missing.redb').exists(),'missing inbox was recreated')
        reply = exchange('initial',{'operation':'bootstrap'},frame(1,initial))
        require(exchange('initial-retry',{'operation':'bootstrap'},frame(1,initial)) == reply,'native reply replay changed')
        final = child.finish(payload(reply,129),now=int(time.time()))
        ready = exchange('final',{'operation':'bootstrap'},frame(2,pair(initial,final)))
        require(exchange('final-retry',{'operation':'bootstrap'},frame(2,pair(initial,final))) == ready,'native READY replay changed')
        session, proof = split(payload(ready,130))
        require(child.activate(now=int(time.time())) == session,'session agreement')
        traffic_head=(session_dir/'head').read_bytes()
        require(child.accept_acknowledgement(proof,now=int(time.time())) == 0,'initial authenticated consumption prefix')
        require((session_dir/'head').read_bytes()==traffic_head,'zero-prefix ACK unexpectedly changed traffic image')

    client,confirmation=connection_checks(client,client_dir,client_id,key,session,proof,root,refuse,(initial,reply,final,ready))
    client.close(); client=EnrollmentClient.open(client_dir,client_id,key)
    require(client.status()['journal'] == original_journal,'client journal changed on reopen')
    with client.connection_session(int(time.time())) as child:
        message=child.next_id(now=int(time.time()))
        plaintext=b'original native reference delivery'; ad=b'actual-time reference'
        ciphertext=child.send(message,plaintext,ad,now=int(time.time()))
        request=frame(3,pair(ad,ciphertext)); operation={'operation':'message','session':list(session)}
        ack=exchange('message',operation,request)
        require(exchange('message-retry',operation,request)==ack,'native consumed reply changed')
        child.accept_acknowledgement(payload(ack,131),now=int(time.time()))
        require(child.status(message)=='Acknowledged','delivery was not authenticated')
        run([session_cli,'read-inbox',root/'inbox.redb',b64(bytes(accepted['journal'])),b64(session),b64(message),root/'received.bin'],'read-delivery')
        require((root/'received.bin').read_bytes()==plaintext,'host effect differs')
        kills=crash_cuts(child,session,bytes(accepted['journal']),root,crash_probe,session_cli,
            make_invocation,exchange,run,commands,frame,pair,payload,b64)
        target, control=child.start_rekey_control(1,now=int(time.time()))
        attempts=0
        while control is not None:
            require(target==1 and attempts<4,'control bound or target'); attempts+=1
            _, original=child.replay_rekey_control(control,now=int(time.time()))
            response=payload(exchange('control-'+str(attempts),{'operation':'control','session':list(session)},frame(4,original)),132)
            if response==b'\0': target,control=child.advance_rekey_control(1,now=int(time.time()))
            else:
                require(response[0]==1,'control response discriminator')
                target,control=child.receive_rekey_control(response[1:],now=int(time.time()))
        require(target==1,'wrong completed epoch')
        next_message=child.next_id(now=int(time.time()))
        next_wire=child.send(next_message,b'after PQ rekey',ad,now=int(time.time()))
        ack=exchange('epoch-one-message',operation,frame(3,pair(ad,next_wire)))
        child.accept_acknowledgement(payload(ack,131),now=int(time.time()))
        require(child.status(next_message)=='Acknowledged','epoch-one delivery was not authenticated')
    client.close(); client=EnrollmentClient.open(client_dir,client_id,key)
    require(client.confirm_connection(session,proof,int(time.time()))==session,'historical confirmation after rekey differs')
    with client.connection_session(int(time.time())) as child:
        require(child.connection_identity(int(time.time()))==session,'reopened epoch-one connection differs')
        require(child.status(next_message)=='Acknowledged','reopened epoch-one status differs')
    confirmation['post_rekey_reopen']=True
    client,last_message,last_plaintext,flow=connection_flow(client,client_dir,client_id,key,session,ack,exchange,refusals)
    run([session_cli,'read-inbox',root/'inbox.redb',b64(bytes(accepted['journal'])),b64(session),b64(last_message),
         root/'facade-received.bin'],'facade-read-delivery')
    require((root/'facade-received.bin').read_bytes()==last_plaintext,'owned connection host effect differs')
    client,inbound=inbound_flow(client,client_dir,client_id,key,session,root,outgoing,run,commands,refusals)
    with client.reopen_connection(Run()) as connection:
        message=connection.next_id(Run()); body=b'independent return after native-driven rekey'
        def carrier(request,deadline,_cancel):
            return exchange('duplex-return',{'operation':'message','session':list(session)},request,deadline=deadline)
        require(connection.deliver(message,body,b'duplex',carrier,Run()) is Consumption.CONFIRMED,'reverse epoch-three delivery')
    run([session_cli,'read-inbox',root/'inbox.redb',b64(bytes(accepted['journal'])),b64(session),b64(message),
         root/'duplex-received.bin'],'duplex-read-delivery')
    require((root/'duplex-received.bin').read_bytes()==body,'duplex host effect differs')
    require({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (device,session_cli,crash_probe,outgoing)}==native_hashes,'native executable changed')
    report={'schema_version':5,'kind':'qperiapt.native_reference_exchange','completed':True,
            'native_sha256':native_hashes,'commands':commands,'refusals':refusals,
            'process_kills':kills,
            'connection_confirmation':confirmation,
            'connection_operations':flow,
            'inbound_operations':inbound,
            'provider':provider.__version__,'implementation':str(implementation/'qperiapt_continuity_reference/publication.py'),
            'confirmed_epoch':inbound['confirmed_epoch'],'control_exchanges':attempts+flow['control_exchanges']+inbound['control_exchanges'],'clock':'actual OS time',
            'scope':'Explicit test authority; separate original native and independent owners, bidirectional owned delivery and three PQ rekeys, durable host effects and consumed-prefix reconciliation, five original store/effect SIGKILL cuts plus five interrupted native senders around independent consumption/reply loss. Bounded file carrier; no physical power-loss, deployed network or real account action.'}
    save(root/'RESULT.json',report); print(json.dumps(report))
finally:
    client.close()
