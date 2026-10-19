"""Actual native-to-independent delivery, effects and control; no substitute keys."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import time
from cryptography.exceptions import InvalidTag
from native_outgoing_driver import Driver,Effects
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.connection_run import Run,Cancellation,Cancelled
from qperiapt_continuity_reference.connection_wire import frame,payload,pair,split
from qperiapt_continuity_reference.wire import require


def exercise(client,path,identity,key,session,root,binary,run,commands,refusals):
    driver=Driver(root,binary,session,run,commands,refusals)
    effects=Effects(root/'independent-effects.sqlite'); connection=client.reopen_connection(Run())
    ad=b'native-to-independent'; events=[]; expected={}

    def reopen():
        nonlocal client,connection
        client.close(); client=EnrollmentClient.open(path,identity,key); connection=client.reopen_connection(Run())
        require(connection.identity==session,'inbound recovery changed session')

    def serve(request,consumer=effects.commit,invocation=None):
        return connection.serve_message(request,consumer,Run() if invocation is None else invocation)

    def expect(label,action):
        try: action()
        except (ValueError,InvalidTag): refusals.append(label)
        else: raise ValueError('missing inbound refusal: '+label)

    def action(message,body):
        require(message not in expected or expected[message]==body,'test changed original native submission')
        expected[message]=body
        return {'operation':'deliver','message':list(message),'plaintext':list(body),'associated_data':list(ad)}

    message=driver.next('inbound-next-empty')
    result=driver.drive('inbound-empty',action(message,b''),serve)
    require(result=={'consumption':'Confirmed'} and effects.read(session,message)==b'','empty delivery failed')
    first=driver.requests['inbound-empty'][0]; calls=effects.calls
    ack=serve(first); require(effects.calls==calls,'consumed replay repeated application effect')
    a,cipher=split(payload(first,3)); changed=cipher[:-1]+bytes([cipher[-1]^1])
    require(serve(frame(3,pair(a,changed)))==ack and effects.calls==calls,'historical prefix delivered replacement bytes')
    # Consumed history still requires bounded/canonical route, direction, epoch
    # and original session. It never bypasses those checks.
    bad_direction=cipher[:40]+b'\1'+cipher[41:]
    expect('inbound-consumed-direction',lambda:serve(frame(3,pair(a,bad_direction)))); reopen()
    bad_session=cipher[:8]+bytes([cipher[8]^1])+cipher[9:]
    expect('inbound-consumed-session',lambda:serve(frame(3,pair(a,bad_session)))); reopen()
    expect('inbound-malformed-frame',lambda:serve(first[:-1])); reopen()
    connection.close()
    with client.session(int(time.time())) as child:
        expect('inbound-legacy-receive-retired',lambda:child.receive(cipher,a,int(time.time())))
    reopen()
    events.append('empty-and-consumed-prefix')

    def fail_before(*_args): raise OSError('injected application failure before effect')
    message=driver.next('inbound-next-before')
    driver.drive('inbound-before',action(message,b'before effect'),lambda r:serve(r,fail_before),receiver_error=OSError)
    require(effects.count()==1,'failed application callback wrote an effect'); reopen()
    require(driver.status('inbound-before-status',message)=='Committed','failed consumer was acknowledged')
    require(driver.drive('inbound-before-retry',action(message,b'before effect'),serve)=={'consumption':'Confirmed'},'pending delivery recovery')
    require(driver.requests['inbound-before']==driver.requests['inbound-before-retry'],'pending retry changed native ciphertext')
    events.append('pending-effect-recovery')

    def fail_after(s,m,p): effects.commit(s,m,p); raise OSError('injected failure after application commit')
    message=driver.next('inbound-next-after')
    driver.drive('inbound-after',action(message,b'after effect'),lambda r:serve(r,fail_after),receiver_error=OSError)
    require(effects.read(session,message)==b'after effect' and effects.count()==3,'committed effect missing'); calls=effects.calls; reopen()
    require(driver.drive('inbound-after-retry',action(message,b'after effect'),serve)=={'consumption':'Confirmed'},'unknown effect recovery')
    require(effects.count()==3 and effects.calls==calls+1,'host deduplication did not reconcile original effect')
    require(driver.requests['inbound-after']==driver.requests['inbound-after-retry'],'unknown effect retry changed ciphertext')
    events.append('effect-deduplication-after-error')

    message=driver.next('inbound-next-lost')
    driver.drive('inbound-lost',action(message,b'lost response'),serve,lose_reply=True)
    require(effects.read(session,message)==b'lost response','lost response had no committed effect'); calls=effects.calls; reopen()
    require(driver.status('inbound-lost-status',message)=='Committed','lost response inferred ACK')
    require(driver.drive('inbound-lost-retry',action(message,b'lost response'),serve)=={'consumption':'Confirmed'},'consumed response replay')
    require(effects.calls==calls,'consumed response replay repeated consumer')
    events.append('consumed-response-loss')

    # Retain a valid prefix without consuming the next wire. The sender can
    # submit its following ID; consuming it out of order retains its commitment.
    old_ack=serve(driver.requests['inbound-lost'][0])
    missing=driver.next('inbound-next-gap')
    require(driver.drive('inbound-gap',action(missing,b'gap'),lambda _:old_ack)=={'consumption':'PrefixPending'},'old prefix claimed gap consumption')
    later=driver.next('inbound-next-later')
    require(driver.drive('inbound-later',action(later,b'out of order'),serve)=={'consumption':'PrefixPending'},'out-of-order prefix claimed contiguous consumption')
    later_wire=driver.requests['inbound-later'][0]; calls=effects.calls
    serve(later_wire); require(effects.calls==calls,'out-of-order consumed replay repeated effect')
    a,cipher=split(payload(later_wire,3));changed=cipher[:-1]+bytes([cipher[-1]^1])
    expect('inbound-retained-commitment',lambda:serve(frame(3,pair(a,changed)))); reopen()
    serve(driver.requests['inbound-gap'][0])
    require(driver.drive('inbound-gap-retry',action(missing,b'gap'),serve)=={'consumption':'Confirmed'},'gap recovery')
    require(driver.status('inbound-later-status',later)=='Acknowledged','contiguous prefix failed to consume later original ID')
    events.append('out-of-order-consumed-commitment')

    message=driver.next('inbound-next-cancel'); cancel=Cancellation(); invocation=Run(cancellation=cancel)
    def cancelled(s,m,p): effects.commit(s,m,p); cancel.cancel()
    driver.drive('inbound-cancel',action(message,b'cancelled effect'),lambda r:serve(r,cancelled,invocation),receiver_error=Cancelled)
    require(effects.read(session,message)==b'cancelled effect','cancelled effect missing'); count=effects.count(); reopen()
    require(driver.drive('inbound-cancel-retry',action(message,b'cancelled effect'),serve)=={'consumption':'Confirmed'},'cancelled effect recovery')
    require(effects.count()==count,'cancel retry duplicated host effect')
    events.append('cancel-after-effect')

    message=driver.next('inbound-next-false')
    driver.drive('inbound-false',action(message,b'consumer refusal'),lambda r:serve(r,lambda *_:False),receiver_error=ValueError)
    require(effects.count()==7,'false consumer result counted as effect'); reopen()
    require(driver.drive('inbound-false-retry',action(message,b'consumer refusal'),serve)=={'consumption':'Confirmed'},'false consumer recovery')
    events.append('explicit-consumer-result')

    done=driver.drive('inbound-rekey',{'operation':'rekey','target':3,'exchanges':4},lambda r:connection.serve_control(r,Run()))
    require(done=={'epoch':3,'exchanges':3},'native-driven original rekey did not complete epoch three')
    connection.close(); reopen()
    message=driver.next('inbound-next-epoch-three'); body=b'native after inbound PQ rekey'
    require(driver.drive('inbound-epoch-three',action(message,body),serve)=={'consumption':'Confirmed'},'native epoch-three delivery')
    require(effects.read(session,message)==body and effects.count()==9,'inbound effect inventory differs')
    require(len(expected)==9 and all(effects.read(session,m)==body for m,body in expected.items()),'complete host effect readback differs')
    connection.close(); events.append('native-driven-rekey-and-delivery')
    return client,{'schema_version':1,'complete':True,'events':events,'interruptions':driver.interruptions,
                   'effect_rows':effects.count(),'consumer_calls':effects.calls,'confirmed_epoch':3,'control_exchanges':3,
                   'host_storage':'SQLite FULL test host; process failure only, no physical power-loss claim'}
