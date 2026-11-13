"""Read elapsed credential expiry separately from immediate HTTP grant recovery.

This reader correlates public execution records. Signature verification remains
in both executing implementations; receipt consistency is not a clock oracle.
"""
import math
from continuity_independent_python import require
from continuity_host_roster_policy import wire

REFUSALS=['peer-expiry-refused','native-expiry-refused']
TIMES={'native_until','peer_until','started_at','observed_at','policy_until'}


def verify(value):
    require(type(value) is dict and set(value)==TIMES|{'elapsed_seconds','operations_refused','original_account_reauthenticated'},
            'elapsed HTTP cohort observation schema')
    require(all(type(value[k]) is int and value[k]>0 for k in TIMES),'elapsed HTTP cohort timestamp type')
    elapsed=value['elapsed_seconds'];start=value['started_at'];now=value['observed_at']
    require(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<elapsed<=3705,
            'elapsed HTTP cohort monotonic bound')
    require(start<min(value['native_until'],value['peer_until']) and now>max(value['native_until'],value['peer_until'])
            and abs((now-start)-elapsed)<=2,'both original credentials must expire through actual elapsed time')
    require(value['policy_until']>now+600,'elapsed HTTP cohort policy expired with credentials')
    require(value['operations_refused']==REFUSALS and value['original_account_reauthenticated'] is True,
            'elapsed HTTP cohort refusal or original authentication missing')


def retain(value,doc,data,requests,responses):
    observed=doc('EXPIRY_OBSERVATION.json');verify(observed)
    require(observed==value['expiry'],'elapsed HTTP cohort retained observation differs')
    waiting=doc('EXPIRY_WAIT.json')
    require(type(waiting) is dict and set(waiting)=={'pid','started_at','target','policy_until','native_until','peer_until','services'},
            'elapsed HTTP cohort wait schema')
    for key in ('started_at','policy_until','native_until','peer_until'):
        require(type(waiting[key]) is int and waiting[key]==observed[key],'elapsed HTTP cohort original wait changed')
    require(type(waiting['target']) is int and waiting['target']==max(observed['native_until'],observed['peer_until'])+1,
            'elapsed HTTP cohort target differs')
    services=waiting['services']
    require(type(services) is dict and set(services)=={'account','probe','witness'},'elapsed HTTP cohort service inventory')
    pids=[waiting['pid'],*services.values()]
    require(all(type(pid) is int and pid>0 for pid in pids) and len(set(pids))==4,
            'elapsed HTTP cohort original process identities')
    require(services['account']==value['account_services'][0]['pid'] and services['witness']==value['witness_services'][0]['pid'],
            'elapsed HTTP cohort service replaced during wait')
    require(doc('EXPIRY_PROGRESS.json')==dict(waiting,phase='expired-and-refused',**observed),
            'elapsed HTTP cohort wait did not reach refusal boundary')
    policy=doc('policy-request.json')
    require(type(policy['valid_from']) is int and type(policy['valid_until']) is int
            and policy['valid_from']<=observed['started_at'] and policy['valid_until']==observed['policy_until']
            and policy['valid_until']-policy['valid_from']==7200,'elapsed HTTP cohort signed test-policy interval')
    plan=doc('native-plan.json')
    require(type(plan['valid_until']) is int and plan['valid_until']<observed['observed_at'],
            'elapsed HTTP cohort original publication has not expired')
    for label in ('native','peer'):
        invitation=doc(label+'-invitation.json');initial=doc(label+'-issued.json')
        start,end=invitation['valid_from'],invitation['valid_until']
        require(type(start) is int and type(end) is int and end-start==3600 and end==observed[label+'_until'],
                'elapsed HTTP cohort initial HTTP credential interval')
        certificate=wire(initial['certificate'])
        require(len(certificate)>2101 and certificate[:4]==(2097).to_bytes(4,'big')
                and certificate[4:12]==b'QPCERT01' and int.from_bytes(certificate[68:76],'big')==start
                and int.from_bytes(certificate[76:84],'big')==end,'elapsed HTTP cohort invitation/certificate interval differs')
    # This required-witness profile authenticates current authority before local
    # admission. The witness denies its expired credential interval first.
    require(data('peer-expiry-refused.stderr')==b'ValueError: witness current authority denied\n'
            and data('native-expiry-refused.stderr')==b'Error: Validity\n',
            'elapsed HTTP cohort failure is not the expected validity refusal')
    require(requests['expiry-old-login']['route']=='/api/me' and responses['expiry-old-login']['status']==401
            and responses['expiry-relogin']=={'authenticated':'original_software_test_passkey'},
            'elapsed HTTP cohort must reauthenticate the original account')
