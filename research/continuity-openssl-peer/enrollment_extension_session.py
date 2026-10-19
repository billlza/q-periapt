#!/usr/bin/env python3
"""Original expired enrollment to independent/native traffic, with fixture authority.

The native issuer retains original C/P until160 and publishes Cnext/Pnext.
Both peers bootstrap at210 and exchange traffic at220. No live account is used.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time


def file_hashes(path):
    return {p.relative_to(path).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(path.rglob('*')) if p.is_file()}


def exercise(args, profile):
    from enrollment_extension_fixture import encoded, b64, grant
    from fixture_inputs import load, load_witness_pin, read_public
    from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
    from qperiapt_continuity_reference.registration_inputs import Inputs
    from qperiapt_continuity_reference.registration_protocol import Intent
    from qperiapt_continuity_reference.wire import require
    from qperiapt_continuity_reference.witness import TcpTransport
    from run import Counterpart
    from traffic_checks import application
    from witness_fixture import Bridge

    out = args.output/profile; out.mkdir(); native_out = out/'native'; native_out.mkdir()
    private = Path(tempfile.mkdtemp(prefix='qperiapt-extension-session-')).resolve()
    (out/'private-fixture-path').write_text(str(private)+'\n')
    client_path, session_path = private/'client', private/'session'
    client_path.mkdir(mode=0o700); session_path.mkdir(mode=0o700)
    identity, wrapping = os.urandom(32), os.urandom(32)
    with os.fdopen(os.open(private/'host-key-and-id', os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as file:
        file.write(wrapping+identity); file.flush(); os.fsync(file.fileno())
    native = Counterpart(args.native,native_out,registration=True,registration_extension=True,
                         required_witness=profile=='witness')
    client = None; bridge = None; refusals = []
    def reopen(): return EnrollmentClient.open(client_path,identity,wrapping)
    def transport(): return None if bridge is None else TcpTransport(bridge.address)
    def call(name,command,wire=b'',expected=None,status=1):
        return (native.command(name,command,wire,status,expected) if bridge is None else
                bridge.call(name,command,wire,expected,status))
    def refuse(name,operation,reason):
        try: operation()
        except ValueError as error:
            require(reason in str(error),'wrong refusal for '+name+': '+str(error))
            refusals.append({'case':name,'error':str(error)})
        else: raise ValueError('missing refusal for '+name)

    try:
        deadline=time.monotonic()+30; size=int.from_bytes(native.read(4,deadline),'big')
        require(size==2058,'native intent size'); wire=native.read(size,deadline)
        require(wire[0]==1,'native intent status'); intent=Intent.from_trusted(wire[1:])
        require(intent.validity.start==100 and intent.validity.end==160,'original expired interval')
        authority={'schema':'qperiapt-host-authority/1','application':list(os.urandom(32)),
                   'root_revision':1,'root':b64(intent.root.raw),'family':list(intent.family)}
        invitation={'operation':list(os.urandom(32)),'request_id':list(os.urandom(32)),
                    'application':authority['application'],'root_revision':1,'root':authority['root'],
                    'family':authority['family'],'device':list(intent.device),'generation':intent.generation,
                    'valid_from':100,'valid_until':160,'deadline':160,'predecessor':None}
        client=EnrollmentClient.begin(client_path,identity,wrapping,encoded(authority),encoded(invitation),150)
        proof=client.request(150); original_identity=client.status()
        require(native.transfer(proof)==b'\1ready','native issuance')
        public=native_out/'public'; original_files=file_hashes(public)
        if profile=='witness': bridge=Bridge(native,out)
        witness=load_witness_pin(public) if bridge is not None else None
        pins, materials, _ = load(public,210,witness_pin=witness)
        require(read_public(public,'extension-clocks')==(210).to_bytes(8,'big')+(220).to_bytes(8,'big'),'native fixture clocks')
        bundle=grant(public,authority,invitation,pins,materials,witness)
        journal=client.accept(*bundle.original,150)
        before=file_hashes(client_path)
        refuse('expired-original-policy',lambda:client.refresh_roster(*bundle.refresh,210),'expired')
        client=reopen(); require(file_hashes(client_path)==before,'expiry refusal changed original state')
        grant_args=bundle.extension
        require(client.adopt_extension(*grant_args,210)==journal,'extension changed future journal')
        client.close(); saved=file_hashes(client_path); client=reopen()
        require(client.adopt_extension(*grant_args,210)==journal and file_hashes(client_path)==saved,'extension retry changed original target')
        genesis=client.prepare(session_path,Inputs(pins,materials,witness),210)
        if bridge is not None: call('independent-witness-enrollment',30,genesis,b'enrolled')
        with client.session(210,transport=transport()) as child:
            initial=child.initial(now=210); reply=call('initial',4,initial)
            call('native-reopen-before-final',12,expected=b'reopened')
            require(call('initial-replay',4,initial)==reply,'native reply replay changed')
            final=child.finish(reply,now=210); session=call('final',5,final)
            require(child.activate(now=210)==session,'session agreement')
            call('native-activate',6,expected=session)
        if bridge is not None: call('witness-traffic-time',33,(220).to_bytes(8,'big'),b'witness clock set')
        with client.session(220,transport=transport()) as child:
            message=child.next_id(now=220); ciphertext=child.send(message,b'after original expiry',b'extended',now=220)
            call('native-receive',7,application(b'extended',ciphertext),b'after original expiry')
            reverse=call('native-next',8); reverse_wire=call('native-send',9,reverse+application(b'extended',b'native after expiry'))
            require(child.receive(reverse_wire,b'extended',now=220)==(reverse,b'native after expiry'),'independent receive')
            acknowledgement=child.consume(reverse,now=220)
            call('native-acknowledgement',11,acknowledgement,(1).to_bytes(8,'big'))
            offer=child.prepare_rekey_offer(now=220); response=call('rekey-response',14,offer)
            confirmation=child.accept_rekey_response(response,now=220); receipt=call('rekey-receipt',15,confirmation)
            require(child.accept_rekey_receipt(receipt,now=220)==1,'confirmed PQ epoch')
        client.close(); client=reopen(); call('native-reopen-after-rekey',12,expected=b'reopened')
        with client.session(220,transport=transport()) as child:
            require(child.resume(message,now=220)==ciphertext,'original ciphertext after rekey/reopen')
            next_id=child.next_id(now=220); next_wire=child.send(next_id,b'new epoch traffic',b'extended',now=220)
            call('native-new-epoch',7,application(b'extended',next_wire),b'new epoch traffic')
        snapshot=file_hashes(client_path)
        refuse('selected-installation-refuses-extension',lambda:client.adopt_extension(*grant_args,220),'child was already prepared')
        client=reopen(); require(file_hashes(client_path)==snapshot,'retarget refusal changed state')
        def expired():
            with client.session(301,transport=transport()) as child: child.next_id(now=301)
        refuse('extended-credential-expiry',expired,'expired')
        client.close(); client=reopen(); final_status=client.status()
        require(final_status['phase']=='Active' and final_status['journal']==journal
                and final_status['signing_id']==original_identity['signing_id']
                and final_status['public_key']==original_identity['public_key'],'original device lineage')
        require(all(file_hashes(public).get(n)==v for n,v in original_files.items()),'retained public issuance changed')
        result={'completed':True,'profile':profile,'native_commands':len(native.commands),
                'witness_requests':0 if bridge is None else len(bridge.records),
                'refusal_cases':[r['case'] for r in refusals],'bootstrap_time':210,'traffic_time':220,
                'original_expiry':160,'extended_expiry':300,'confirmed_epoch':1,
                'journal':journal.hex(),'session':session.hex(),'request_sha256':hashlib.sha256(proof).hexdigest(),
                'original_ciphertext_sha256':hashlib.sha256(ciphertext).hexdigest(),
                'scope':'Independent EnrollmentClient extension to real native durable handshake, bidirectional traffic, PQ rekey and owner reopen. Explicit fixture authority/clocks and loopback witness bridge; no live account, production TLS, power loss or release claim.'}
        (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
        return {k:result[k] for k in ('completed','profile','native_commands','witness_requests','refusal_cases',
                                     'bootstrap_time','traffic_time','original_expiry','extended_expiry','confirmed_epoch')}
    finally:
        if client is not None: client.close()
        if bridge is not None:
            (out/'WITNESS.json').write_text(json.dumps(bridge.records,indent=2)+'\n'); bridge.close()
        (out/'NATIVE.json').write_text(json.dumps(native.commands,indent=2)+'\n')
        (out/'REFUSALS.json').write_text(json.dumps(refusals,indent=2)+'\n')
        native.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root','provider-root','native','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(); args.implementation_root=args.implementation_root.resolve(strict=True)
    sys.path.insert(0,str(args.implementation_root))
    from qperiapt_continuity_reference.provider import load_provider
    provider,_=load_provider(args.provider_root)
    from qperiapt_continuity_reference import enrollment_client
    require_path=Path(enrollment_client.__file__).resolve()
    if not require_path.is_relative_to(args.implementation_root): raise ValueError('wrong installed implementation')
    args.output.mkdir()
    result={'schema_version':1,'kind':'qperiapt.enrollment_extension_session',
            'completed':True,'provider':provider.__version__,'implementation':str(require_path),
            'native_sha256':hashlib.sha256(args.native.read_bytes()).hexdigest(),
            'profiles':[exercise(args,label) for label in ('local','witness')]}
    (args.output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result))


if __name__=='__main__': main()
