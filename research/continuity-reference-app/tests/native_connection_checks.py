"""Actual READY authentication, original-store recovery and bounded SIGKILL cuts."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import os
import signal
import time

from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require


def exercise(client, path, identity, key, session, proof, root, refuse):
    def open_original(observer=None):
        return EnrollmentClient.open(path,identity,key,observer=observer)

    def files():
        return {str(p.relative_to(path)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in path.rglob('*') if p.is_file()}

    original=client.status()
    require(client.connection_confirmation() is None,'raw Traffic inferred peer confirmation')
    before=files()
    refuse('unrecorded-connection',lambda:client.connection_session(int(time.time())))
    require(files()==before,'missing confirmation changed registration')
    client=open_original()
    changed=proof[:-1]+bytes([proof[-1]^1])
    refuse('forged-ready',lambda:client.confirm_connection(session,changed,int(time.time())))
    require(files()==before,'forged confirmation changed registration')
    client=open_original()
    other=bytes([session[0]^1])+session[1:]
    refuse('wrong-ready-session',lambda:client.confirm_connection(other,proof,int(time.time())))
    require(files()==before,'wrong confirmation scope changed registration')
    client=open_original()

    # Host cancellation at a real prepublication boundary must close both owners
    # and withhold the result. Unpublished staging is retained for diagnosis.
    stage='client-device:registration-store:stage-synced:intent'
    client.close()
    def close_at_stage(observed):
        if observed==stage: client.close()
    client=open_original(close_at_stage)
    refuse('confirmation-close-during-write',lambda:client.confirm_connection(session,proof,int(time.time())))
    client=open_original()
    require(client.connection_confirmation() is None,'unpublished confirmation was promoted')
    require(client.status()==original,'cancellation changed original registration')
    client.close()

    kills=[]
    for cut in ('stage-synced:intent','committed:intent'):
        observed_stage='client-device:registration-store:'+cut
        marker=root/('confirmation-'+cut.replace(':','-')+'.ready')
        pid=os.fork()
        if pid==0:
            # A missed callback must fail in bounded time, never hang the runner.
            signal.alarm(30)
            def kill_at_stage(observed):
                if observed!=observed_stage: return
                raw=f'{os.getpid()} {observed}\n'.encode()
                with os.fdopen(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
                    out.write(raw); out.flush(); os.fsync(out.fileno())
                os.kill(os.getpid(),signal.SIGKILL)
            try:
                child=open_original(kill_at_stage)
                child.confirm_connection(session,proof,int(time.time()))
                child.close()
            except BaseException: os._exit(71)
            os._exit(72)
        _,status=os.waitpid(pid,0)
        require(os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL,
                'confirmation process missed SIGKILL boundary')
        raw=marker.read_bytes()
        require(raw==f'{pid} {observed_stage}\n'.encode(),'confirmation kill marker differs')
        kills.append({'stage':cut,'pid':pid,'exit':-9,'marker_sha256':hashlib.sha256(raw).hexdigest()})
        if cut=='stage-synced:intent':
            client=open_original()
            require(client.connection_confirmation() is None,'staging inferred confirmation')
            client.close()

    # Recovery has an authenticated formal intent, but its own publication may
    # fail after commit. Retrying open must reconcile that exact original target.
    def fail_recovery(stage):
        if stage=='client-device:registration-store:committed:head':
            raise OSError('injected recovery observer failure after real head commit')
    try: open_original(fail_recovery)
    except OSError as error:
        require(str(error)=='injected recovery observer failure after real head commit','unexpected recovery error')
        recovery_failure=True
    else: raise ValueError('confirmation recovery observer did not fail')
    client=open_original()
    require(client.connection_confirmation()==session,'formal confirmation intent was not recovered')
    require(client.status()==original,'confirmation recovery changed original registration')
    before=files()
    require(client.confirm_connection(session,proof,int(time.time()))==session,'exact confirmation retry differs')
    require(files()==before,'exact confirmation retry wrote registration')
    refuse('conflicting-ready-retry',lambda:client.confirm_connection(session,changed,int(time.time())))
    require(files()==before,'conflicting confirmation mutated original record')
    client=open_original()
    with client.connection_session(int(time.time())) as child:
        require(child.connection_identity(int(time.time()))==session,'confirmed session differs')
        for name in ('initial','finish','activate'):
            require(not hasattr(child,name),'connection exposes bootstrap capability')
        client.close()
        refuse('closed-confirmed-owner',lambda:child.connection_identity(int(time.time())))
    client=open_original()
    return client,{'schema_version':1,'process_kills':kills,'recovery_failure':recovery_failure,
                   'raw_traffic_unrecorded':True,'exact_retry_unchanged':True,'closed_owner_refused':True}
