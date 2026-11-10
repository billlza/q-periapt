"""Read real expired-P0 outcomes without granting new operational authority."""
from pathlib import Path
import continuity_android_contract as contract
import rust_sdk_profile as sdk

TESTS={profile:'android_policy_expiry::'+profile for profile in ('fixed','recoverable')}
COMMON=(("original.request","managed-witness-create"),("authority-created","authority-create"),
 ("genesis","managed-witness-prepare"),("activated.request","managed-witness-activate"),
 ("expiry-original","credential-policy-identity"),("expiry-staged","credential-policy-stage"),
 ("expiry-proposal","credential-policy-prepare"),("expiry-proposal-replayed","credential-policy-prepare-replay"),
 ("expiry-activation-before","credential-policy-activate-expired"),("expiry-stage-refused","credential-policy-stage-expired"),
 ("expiry-history","credential-policy-reconcile"),("expiry-close","credential-policy-close"),
 ("expiry-terminal","credential-policy-reconcile"),("expiry-terminal-replayed","credential-policy-commit-terminal"),
 ("expiry-activation-after","credential-policy-activate-expired"),("expiry-original-after","credential-policy-identity"))
def cases(applied):
    return COMMON+(("expiry-before-expiration","credential-policy-commit-unknown" if applied else "credential-policy-status"),
                   ("expiry-transition","credential-policy-commit-recover" if applied else "credential-policy-commit-expired"))
def public(applied):
    return tuple(n for n,_ in cases(applied))+tuple(n+'.'+s for n,_ in cases(applied) for s in ('stdout','stderr'))+(
     'expiry-observation','expiry-sdk-binding','expiry-historical-transcript','inputs/credential-operation','inputs/credential-statement',
     'inputs/renewal-version','inputs/renewal-digest','inputs/credential-renewal','inputs/expiry-credential-until','inputs/expiry-roster-until',
     'inputs/protocol-policy','inputs/policy-root','inputs/policy-version','inputs/policy-digest','inputs/family',
     'inputs/enrollment-root','inputs/witness-id','inputs/witness-public','inputs/authority-checkpoint')+(
     ('expiry-lost-commit-request','expiry-lost-commit-reply') if applied else ())

def verify_execution(stdout:bytes,directory:Path,profile:str)->dict:
    sdk.require(profile in TESTS,'unknown expiry trust profile');text=stdout.decode();lines=text.splitlines()
    contract.verify_single(stdout, TESTS[profile])
    results={}
    for carrier in ('signed','tls'):
        for outcome in ('closed','applied'):
            applied=outcome=='applied';label=f'{carrier}-{profile}-{outcome}';base=directory/label
            def read(n):return sdk.snapshot(base/n).data
            marker=f'qualified policy expiry {carrier}/{profile}/{outcome}: 18 foreign processes; live SDK and target, expired P0, original history, no fresh commit or activation'
            sdk.require(lines.count(marker)==1,'expired-policy route missing or duplicated')
            for name,mode in cases(applied):
                sdk.require(read(name+'.stdout')==f'{profile}:{mode}:passed\n'.encode() and read(name+'.stderr')==b'','expired-policy process omitted its outcome')
            request=read('original.request');sdk.require(len(request)==5506 and read('activated.request')==request,'original registration changed')
            genesis=read('genesis');identity=read('expiry-original')
            sdk.require(len(genesis)==164 and genesis[:4]==(2).to_bytes(4,'big') and len(identity)==64 and any(identity[:32])
                        and identity[32:]==genesis[4:36] and read('expiry-original-after')==identity,'expired-policy cleanup replaced identity or journal')
            operation,statement=read('inputs/credential-operation'),read('inputs/credential-statement')
            target=read('inputs/renewal-version')+read('inputs/renewal-digest')
            sdk.require(len(operation)==len(statement)==32 and any(operation) and any(statement) and len(target)==40
                        and target[:8]==(2).to_bytes(8,'big') and any(target[8:]),'original credential target malformed')
            scope=operation+statement;pending=(1).to_bytes(4,'big')+scope+bytes(48)
            committed=(2).to_bytes(4,'big')+scope+target+bytes(8)
            closed=(4).to_bytes(4,'big')+scope+target+bytes(8)
            sdk.require(read('expiry-staged')==pending,'original pending target missing')
            sdk.require(read('expiry-before-expiration')==((218).to_bytes(4,'big') if applied else pending),'pre-expiry outcome differs')
            sdk.require(read('expiry-transition')==(committed if applied else (104).to_bytes(4,'big'))
                        and read('expiry-history')==(committed if applied else pending),'historical recovery guessed an unobserved commit')
            terminal=committed if applied else closed
            sdk.require(all(read(n)==terminal for n in ('expiry-close','expiry-terminal','expiry-terminal-replayed')),'terminal history changed')
            sdk.require(all(read(n)==(104).to_bytes(4,'big') for n in ('expiry-stage-refused','expiry-activation-before','expiry-activation-after')),'expired P0 granted a new operation')
            proposal=read('expiry-proposal');sdk.require(len(proposal)==296 and read('expiry-proposal-replayed')==proposal,'expiry changed the original proposal')
            observation=read('expiry-observation');sdk.require(len(observation)==40,'real policy expiry observation missing')
            until,at,credential,roster,enabled=(int.from_bytes(observation[i:i+8],'big') for i in range(0,40,8))
            sdk.require(0<until<=at<credential and at<roster and enabled==1 and len(read('expiry-sdk-binding'))==68,'P0 expiry was substituted with target or SDK expiry')
            transcript=read('expiry-historical-transcript');sdk.require(0<len(transcript)<=128*7334 and len(transcript)%7334==0,'historical transcript frame bound')
            ops=[]
            for offset in range(0,len(transcript),7334):
                frame=transcript[offset:offset+7334];sdk.require(frame[0]==1 and frame[205]!=5,'expired history dispatched a new Commit or lost an unrecorded reply');ops.append(frame[205])
            sdk.require(ops.count(7)==(0 if applied else 1),'explicit closure or competing Applied outcome changed')
            if applied:
                request,reply=read('expiry-lost-commit-request'),read('expiry-lost-commit-reply')
                sdk.require(len(request)==3674 and request[204]==5 and len(reply)==3659 and reply[204]==8,'Applied lacks its real pre-expiry commit exchange')
            results[label]={'foreign_processes':len(cases(applied)),'policy_expired':True,'sdk_live':True,'target_live':True,'terminal':'Committed' if applied else 'Closed','new_commit_after_expiry':False,'activation_after_expiry':False}
    return results
