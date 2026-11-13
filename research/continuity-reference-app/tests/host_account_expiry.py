"""Bounded actual-time expiry barrier for original HTTP-issued credentials.

Only test-policy validity is selected at issuance. No device/SDK clock input is
overridden. Existing processes, keys, sessions and pending ciphertext survive.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import math
import os
import signal
import time
from native_exchange_fixture import save
from qperiapt_continuity_reference.wire import require


def validate(value):
    for key in ('native_until','peer_until','started_at','observed_at','policy_until'):
        require(type(value[key]) is int and value[key]>0,'expiry timestamp type')
    elapsed=value['elapsed_seconds']
    require(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<=3705,'bounded monotonic expiry interval')
    target=max(value['native_until'],value['peer_until'])+1
    require(value['started_at']<min(value['native_until'],value['peer_until'])
            and value['observed_at']>=target and elapsed+2>=target-value['started_at'],
            'both credentials must expire through actual elapsed time')
    require(value['policy_until']>value['observed_at']+600,'credential-only expiry requires a still-live policy')


def observe(root,native,peer,host,probe,witness,run,session):
    started=int(time.time());monotonic=time.monotonic()
    until={'native_until':native.invitation['valid_until'],'peer_until':peer.invitation['valid_until']}
    for endpoint in (native,peer):
        require(endpoint.invitation['valid_until']-endpoint.invitation['valid_from']==3600,
                'HTTP credential validity default changed')
    target=max(until.values())+1
    require(started<min(until.values()) and target-started<=3601,'bounded initial expiry wait')
    policy=json.loads((root/'policy-request.json').read_bytes())
    require(policy['valid_until']>target+600,'signed test policy expires before recovery')
    waiting={'pid':os.getpid(),'started_at':started,'target':target,'policy_until':policy['valid_until'],**until,
             'services':{'account':host.process.pid,'probe':probe.process.pid,'witness':witness.service.process.pid}}
    save(root/'EXPIRY_WAIT.json',waiting)
    deadline=monotonic+3700;next_record=monotonic
    def interrupted(_number,_frame):raise InterruptedError('Elapsed expiry test interrupted; original fixtures retained')
    previous=signal.signal(signal.SIGTERM,interrupted)
    try:
        while int(time.time())<target:
            now=time.monotonic();require(now<deadline,'actual expiry wait exceeded its monotonic bound')
            require(host.process.poll() is None and probe.process.poll() is None
                    and witness.service.process.poll() is None,'original service exited during expiry wait')
            if now>=next_record:
                (root/'EXPIRY_PROGRESS.json').write_text(json.dumps(dict(waiting,phase='waiting',observed_at=int(time.time()),elapsed_seconds=now-monotonic))+'\n')
                next_record=now+30
            time.sleep(min(1,max(0,deadline-now)))
        value={**until,'started_at':started,'observed_at':int(time.time()),'elapsed_seconds':time.monotonic()-monotonic,
               'policy_until':policy['valid_until']}
        validate(value)
        peer.next(session,'expiry-refused',success=False)
        run([native.binary,'activate',*native.active_args],'native-expiry-refused',success=False)
        probe.request('alice','expiry-old-login','/api/me',status=401)
        probe.login('alice','expiry-relogin')
        value.update(operations_refused=['peer-expiry-refused','native-expiry-refused'],original_account_reauthenticated=True)
        save(root/'EXPIRY_OBSERVATION.json',value)
        (root/'EXPIRY_PROGRESS.json').write_text(json.dumps(dict(waiting,phase='expired-and-refused',**value))+'\n')
        return value
    finally:signal.signal(signal.SIGTERM,previous)
