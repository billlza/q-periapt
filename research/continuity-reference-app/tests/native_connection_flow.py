"""Owned application operations against the original native peer at real OS time."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import time
import threading
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.connection import Consumption
from qperiapt_continuity_reference.connection_run import Run, Cancellation, Cancelled, ExchangeLimit
from qperiapt_continuity_reference.connection_wire import frame, payload, split, acknowledgement_epoch
from qperiapt_continuity_reference.wire import require


def boundaries():
    checks=[]
    for label,action in (
        ('zero-timeout',lambda:Run(0)),('negative-timeout',lambda:Run(-1)),
        ('boolean-timeout',lambda:Run(True)),('nan-timeout',lambda:Run(float('nan'))),
        ('infinite-timeout',lambda:Run(float('inf'))),('excessive-timeout',lambda:Run(121)),
        ('frame-capacity',lambda:frame(3,bytes(32760))),
        ('reply-capacity',lambda:payload(b'QPCXCH01\x83'+bytes(32760),131)),
        ('truncated-pair',lambda:split(b'\0\3x')),
        ('zero-v2-epoch',lambda:acknowledgement_epoch(b'QPCMACK2'+bytes(81)))):
        try: action()
        except ValueError: checks.append(label)
        else: raise ValueError('missing connection boundary refusal: '+label)
    cancellation=Cancellation(); cancellation.cancel()
    try: Run(cancellation=cancellation).now()
    except Cancelled: checks.append('pre-cancelled-run')
    else: raise ValueError('pre-cancelled invocation admitted')
    return checks


def exercise(client,path,identity,key,session,prior_ack,exchange,refusals):
    bounds=boundaries()
    connection=client.reopen_connection(Run())
    original=connection.identity
    require(original==session,'connection facade changed original session')
    operation={'operation':'message','session':list(session)}
    ad=b'owned connection operations'; requests={}; events=[]

    def expect(label,error,action):
        try: action()
        except error: refusals.append(label)
        else: raise ValueError('missing connection failure: '+label)

    def reopen():
        nonlocal client,connection
        client.close(); client=EnrollmentClient.open(path,identity,key)
        connection=client.reopen_connection(Run())
        require(connection.identity==original,'reopen replaced original connection')

    def carrier(label,op=operation):
        def call(request,deadline,cancellation):
            require(deadline>time.monotonic() and not cancellation.is_cancelled(),'carrier invocation expired')
            requests[label]=request
            return exchange(label,op,request,deadline=deadline)
        return call

    message=connection.next_id(Run())
    def pending(request,deadline,cancellation):
        expect('facade-reentrant-operation',ValueError,lambda:connection.next_id(Run()))
        requests['pending']=request
        # This is a retained authentic epoch-one ACK. Its prefix does not cover
        # this new ID. It must be reported as pending, never successful delivery.
        return prior_ack
    require(connection.deliver(message,b'prefix pending',ad,pending,Run()) is Consumption.PREFIX_PENDING,
            'older authenticated prefix incorrectly reported delivery')
    require(connection.status(message)=='Committed','prefix pending changed original send disposition')
    require(connection.resume(message,ad,carrier('facade-pending-resume'),Run()) is Consumption.CONFIRMED,
            'original pending delivery was not confirmed')
    require(requests['pending']==requests['facade-pending-resume'],'pending resume changed ciphertext')
    events.append('authenticated-prefix-pending')

    message=connection.next_id(Run())
    def lost(request,deadline,cancellation):
        carrier('facade-lost-ack')(request,deadline,cancellation)
        raise OSError('injected loss after real peer consumption')
    expect('facade-lost-ack',OSError,lambda:connection.deliver(message,b'lost acknowledgement',ad,lost,Run()))
    expect('facade-closed-owner',ValueError,lambda:connection.status(message)); reopen()
    require(connection.status(message)=='Committed','lost ACK was inferred acknowledged')
    expect('facade-conflicting-submission',ValueError,
           lambda:connection.deliver(message,b'changed original input',ad,carrier('must-not-dispatch'),Run()))
    require('must-not-dispatch' not in requests,'conflicting submission dispatched'); reopen()
    require(connection.resume(message,ad,carrier('facade-lost-resume'),Run()) is Consumption.CONFIRMED,'lost ACK recovery')
    require(requests['facade-lost-ack']==requests['facade-lost-resume'],'lost ACK retry changed ciphertext')
    events.append('lost-ack-exact-recovery')

    message=connection.next_id(Run())
    bad=prior_ack[:-1]+bytes([prior_ack[-1]^1])
    expect('facade-forged-ack',ValueError,lambda:connection.deliver(message,b'forged acknowledgement',ad,lambda *_:bad,Run()))
    reopen(); require(connection.status(message)=='Committed','forged ACK altered send disposition')
    require(connection.resume(message,ad,carrier('facade-forged-resume'),Run()) is Consumption.CONFIRMED,'forged ACK recovery')
    events.append('forged-ack-refused')

    message=connection.next_id(Run()); cancel=Cancellation(); invocation=Run(cancellation=cancel)
    def cancelled(request,deadline,cancellation):
        require(deadline==invocation.deadline and cancellation is cancel,'invocation deadline/token substituted')
        reply=carrier('facade-cancel')(request,deadline,cancellation)
        worker=threading.Thread(target=cancel.cancel); worker.start(); worker.join(timeout=2)
        require(not worker.is_alive(),'cross-thread cancellation did not complete')
        return reply
    expect('facade-cancelled-result',Cancelled,lambda:connection.deliver(message,b'cancelled after commit',ad,cancelled,invocation))
    reopen(); require(connection.status(message)=='Committed','cancelled result escaped as acknowledged')
    require(connection.resume(message,ad,carrier('facade-cancel-resume'),Run()) is Consumption.CONFIRMED,'cancelled delivery recovery')
    require(requests['facade-cancel']==requests['facade-cancel-resume'],'cancelled retry changed ciphertext')
    events.append('cancelled-after-peer-commit')

    message=connection.next_id(Run()); reached=[]
    def late(_request,deadline,_cancellation):
        reached.append(True)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0: break
            time.sleep(min(.02,remaining))
        return prior_ack
    expect('facade-deadline',TimeoutError,lambda:connection.deliver(message,b'expired invocation',ad,late,Run(5)))
    require(reached==[True],'deadline test did not reach the late carrier'); reopen()
    require(connection.resume(message,ad,carrier('facade-timeout-resume'),Run()) is Consumption.CONFIRMED,'deadline recovery')
    events.append('late-result-withheld')

    message=connection.next_id(Run())
    def close(_request,_deadline,_cancellation): client.close(); return prior_ack
    expect('facade-reentrant-close',ValueError,lambda:connection.deliver(message,b'closed during callback',ad,close,Run()))
    reopen()
    require(connection.resume(message,ad,carrier('facade-close-resume'),Run()) is Consumption.CONFIRMED,'closed callback recovery')
    events.append('reentrant-close-withheld')

    expect('facade-false-control',ValueError,lambda:connection.rekey(2,lambda *_:frame(132,b'\0'),Run()))
    reopen(); control={'operation':'control','session':list(session)}
    expect('facade-exchange-limit',ExchangeLimit,
           lambda:connection.rekey(2,carrier('facade-control-limited',control),Run(),exchanges=1))
    reopen(); calls=[]; control_run=Run()
    def control_carrier(request,deadline,cancellation):
        require(deadline==control_run.deadline and cancellation is control_run.cancellation,'control invocation changed')
        calls.append(len(calls)+1)
        return carrier('facade-control-'+str(calls[-1]),control)(request,deadline,cancellation)
    done=connection.rekey(2,control_carrier,control_run,exchanges=4)
    require(done.epoch==2 and done.exchanges==2 and calls==[1,2],'original target recovery did not finish exactly epoch two')
    events.append('bounded-original-rekey-recovery')
    message=connection.next_id(Run()); plaintext=b'after owned connection PQ rekey'
    require(connection.deliver(message,plaintext,ad,carrier('facade-epoch-two'),Run()) is Consumption.CONFIRMED,
            'epoch-two owned delivery not confirmed')
    connection.close(); reopen()
    require(connection.status(message)=='Acknowledged','confirmed post-rekey result did not survive reopen')
    close_child=connection._child.close
    def failed_cleanup():
        close_child()
        raise OSError('injected error after actual child cleanup')
    connection._child.close=failed_cleanup
    expect('facade-close-error',OSError,connection.close)
    reopen(); require(connection.status(message)=='Acknowledged','cleanup error lost original delivery')
    connection.close(); events.append('cleanup-error-releases-owner')
    return client,message,plaintext,{'schema_version':1,'events':events,'confirmed_epoch':2,'control_exchanges':3,
                                   'native_commands':12,'boundary_checks':bounds,'complete':True}
