"""Approved successor against a separately verified native persistent endpoint."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import os
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_retirement_fixture import control,field
from traffic_checks import application


def exercise(client,recovery,registry,plan,*,bridge,now,path,host,mode,refuse,previous_traffic=None):
    later=previous_traffic is not None
    restart_offset=len(bridge.native.restarts)
    expired_prekeys=previous_traffic.get('expired_prekeys') if later else None
    tag='later-successor' if later else 'successor'
    approval,traffic=(56,57) if later else (52,53)
    def transport():return TcpTransport(bridge.address)
    def reopen():return EnrollmentClient.open(path,host[32:],host[:32],account_authority=registry)
    def call(label,command,wire=b'',expected=None,status=1):
        return bridge.call(tag+'-peer-'+label,traffic,bytes([command])+wire,expected,status)
    try:
        _,image=client._registration._image()
        context=image.child.inputs.current(now);materials=image.child.inputs.materials
        decision=recovery._access.observation()[3]
        prefix=control(plan)+field(decision)
        request=prefix+field(materials.manifest)+field(materials.classical_proof)+field(materials.pq_proof)
        require(len(request)+1<=32768,'successor control exceeds original pipe bound')
        public=bridge.native.cases.parent/('public/root-successor-later' if later else 'public/root-successor')
        require(not public.exists(),'fresh successor control already has an endpoint')
        call('before-approval',4,status=2,expected=(b'later successor peer before explicit approval'
                                                  if later else b'successor peer before explicit approval'))
        bridge.call(tag+'-control-truncated',approval,request[:-1],status=2)
        bad=bytearray(decision);bad[-1]^=1
        bridge.call(tag+'-control-uncommitted',approval,control(plan)+field(bytes(bad))
                    +field(materials.manifest)+field(materials.classical_proof)+field(materials.pq_proof),status=2)
        bad=bytearray(materials.manifest);bad[-65]^=1
        bridge.call(tag+'-control-invalid-manifest',approval,prefix+field(bytes(bad))
                    +field(materials.classical_proof)+field(materials.pq_proof),status=2)
        if expired_prekeys is not None:
            bridge.call(tag+'-control-expired-advertisement',approval,
                        prefix+b''.join(field(value) for value in expired_prekeys),status=2)
        require(not public.exists(),'rejected successor control created an endpoint')
        require(bridge.call(tag+'-control-approved',approval,request)==context.digest,
                'independent/native successor context differs')
        original_path=public/'private-fixture-path'
        native_private=original_path.read_bytes()
        require(native_private==(public.parent/'private-fixture-path').read_bytes(),
                'successor peer replaced the original native journal')
        bridge.call(tag+'-retired-original-controller',8,status=2,
                    expected=(b'resumed fixture only admits its original successor' if bridge.native.restarts
                              else b'original peer controller retired; use successor commands'))
        if later:
            bridge.call(tag+'-retired-previous-controller',53,b'\x08',status=2,
                        expected=b'previous successor controller retired')
            original_control=(public.parent/'root-successor/control').read_bytes()
            bridge.call(tag+'-retired-previous-approval',52,original_control,status=2,
                        expected=b'previous successor controller retired')
        require(bridge.call(tag+'-control-exact-retry',approval,request)==context.digest
                and original_path.read_bytes()==native_private,'successor approval replaced native store')
        from native_restart import SuccessorRestarts
        restarts=SuccessorRestarts(bridge,now,request,context.digest,later=later)
        restarts.at('approved')
        with client.session(now,transport=transport()) as child:
            initial=child.initial(now=now)
            reply=call('initial',4,initial)
            restarts.initial,restarts.reply=initial,reply
            restarts.at('reply')
            call('reopen-reply',12,expected=b'reopened')
            require(call('initial-replay',4,initial)==reply,'successor native reply changed on reopen')
            final=child.finish(reply,now=now)
            session=call('finish',5,final)
            restarts.final,restarts.session=final,session
            restarts.at('final')
            require(child.activate(now=now)==session,'successor session identity differs')
            call('activate',6,expected=session)
            restarts.active=True
            restarts.at('active')
            proof=call('ready-proof',13)
        require(client.confirm_connection(session,proof,now,transport=transport())==session,
                'successor peer confirmation was not retained')
        client.close();client=reopen()
        require(client.connection_confirmation()==session,'successor original confirmation changed')
        if later:
            require(session.hex()!=previous_traffic['session'] and context.digest.hex()!=previous_traffic['context'],
                    'later root reused original peer context or session')
            call('previous-root-ciphertext',7,application(bytes.fromhex(previous_traffic['first_ad']),
                 bytes.fromhex(previous_traffic['first_ciphertext'])),status=2)
        message=b'original root successor request';ad=b'successor'
        with client.connection_session(now,transport=transport()) as child:
            identity=child.next_id(now=now)
        pending_digest=completed_digest=None
        if mode in ('peer-before','peer-after'):
            bridge.arm(mode.removeprefix('peer-'),2)
            with client.connection_session(now,transport=transport()) as child:
                refuse('successor-send-unknown-'+mode,lambda:child.send(identity,message,ad,now=now),
                       'truncated witness reply')
            client.close()
            restarts.at('unknown-send')
            intent=(image.child.path/'intent').read_bytes()
            require(intent.startswith(b'QPREFI01'),'unknown successor send lost exact intent')
            size=int.from_bytes(intent[48:52],'big');target=intent[52:52+size]
            require(len(intent)==52+size+32,'unknown successor intent shape')
            pending_digest=hashlib.sha256(target).hexdigest()
            retained=path.parent/'successor-send-original-intent'
            with os.fdopen(os.open(retained,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
                out.write(intent);out.flush();os.fsync(out.fileno())
            client=reopen()
            with client.connection_session(now,transport=transport()) as child:
                require(hashlib.sha256((image.child.path/'head').read_bytes()).hexdigest()==pending_digest,
                        'successor recovery did not publish exact retained reservation')
                ciphertext=child.resume(identity,now=now)
                completed_digest=hashlib.sha256((image.child.path/'head').read_bytes()).hexdigest()
                require(completed_digest!=pending_digest,'successor send did not commit its ciphertext')
                require(child.send(identity,message,ad,now=now)==ciphertext,'successor recovery changed original send')
            require(hashlib.sha256((image.child.path/'head').read_bytes()).hexdigest()==completed_digest,
                    'successor duplicate send changed completed state')
        else:
            with client.connection_session(now,transport=transport()) as child:
                ciphertext=child.send(identity,message,ad,now=now)
        call('receive',7,application(ad,ciphertext),message)
        restarts.at('receive')
        call('reopen-receive',12,expected=b'reopened')
        call('receive-duplicate',7,application(ad,ciphertext),message)
        ack=call('consume',10,identity)
        with client.connection_session(now,transport=transport()) as child:
            require(child.accept_acknowledgement(ack,now=now)==1,'successor outgoing consumption prefix')
        incoming_id=call('next',8)
        incoming=call('send',9,incoming_id+application(ad,b'original native successor response'))
        restarts.at('outbox')
        call('reopen-outbox',12,expected=b'reopened')
        require(call('send-replay',9,incoming_id+application(ad,b'original native successor response'))==incoming,
                'successor native original outbox changed')
        with client.connection_session(now,transport=transport()) as child:
            require(child.receive(incoming,ad,now=now)==(incoming_id,b'original native successor response'),
                    'successor incoming plaintext or identity differs')
            require(child.receive(incoming,ad,now=now)==(incoming_id,b'original native successor response'),
                    'successor duplicate incoming differs')
            ack=child.consume(incoming_id,now=now)
        call('accept-ack',11,ack,(1).to_bytes(8,'big'))
        restarts.at('ack')
        client.close();client=reopen()
        call('reopen-ack',12,expected=b'reopened')
        with client.connection_session(now,transport=transport()) as child:
            require(child.connection_identity(now=now)==session,'successor reopening changed session')
            offer=child.prepare_rekey_offer(now=now);response=call('rekey-response',14,offer)
            restarts.at('rekey-response')
            require(call('rekey-response-replay',14,offer)==response,'native restart changed rekey response')
            final=child.accept_rekey_response(response,now=now);receipt=call('rekey-receipt',15,final)
            restarts.at('rekey-receipt')
            require(call('rekey-receipt-replay',15,final)==receipt,'native restart changed rekey receipt')
            require(child.accept_rekey_receipt(receipt,now=now)==1,'successor rekey did not reach epoch one')
            next_id=child.next_id(now=now)
            encrypted=child.send(next_id,b'after successor rekey',ad,now=now)
            call('receive-new-epoch',7,application(ad,encrypted),b'after successor rekey')
            restarts.at('new-epoch')
            call('receive-new-epoch-replay',7,application(ad,encrypted),b'after successor rekey')
        require(original_path.read_bytes()==native_private,'successor native storage path changed')
        require(bridge.call(tag+'-control-after-traffic',approval,request)==context.digest,
                'successor control retry changed active context')
        return {'completed':True,'mode':mode,'context':context.digest.hex(),'session':session.hex(),
                'directions':2,'peer_confirmation_retained':True,'root_revision':3 if later else 2,'rekey_epoch':1,
                'first_ciphertext':ciphertext.hex(),'first_ad':ad.hex(),'previous_root_traffic_refused':later,
                'native_reopens':4,'unknown_send_reservation_sha256':pending_digest,
                'native_process_restarts':bridge.native.restarts[restart_offset:],
                'completed_send_head_sha256':completed_digest,
                'native_control_refusals':(7 if later else 5)+int(expired_prekeys is not None),
                'expired_previous_advertisement_refused':expired_prekeys is not None,
                'native_original_journal_retained':True,
                'native_private_path_file':str(original_path),
                'scope':'Installed independent client versus original native persistent peer: approved root target, authenticated handshake, two-way traffic, exact replay, consumption, reopening and rekey. Process restarts are counted separately with actual PID/SIGKILL and preserved-file receipts. Native control pipe is test orchestration; no power-loss, mobile or PCS claim.'}
    finally:client.close()
